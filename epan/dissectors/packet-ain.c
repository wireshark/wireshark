/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-ain.c                                                               */
/* asn2wrs.py -b -q -L -p ain -c ./ain.cnf -s ./packet-ain-template -D . -O ../.. AIN-Operations.asn AIN-Errors.asn AIN-Parameters.asn ../ros/Remote-Operations-Information-Objects.asn ../ros/Remote-Operations-Generic-ROS-PDUs.asn */

/* packet-ain-template.c
* Routines for AIN
* Copyright 2018, Anders Broman <anders.broman@ericsson.com>
*
* Wireshark - Network traffic analyzer
* By Gerald Combs <gerald@wireshark.org>
* Copyright 1998 Gerald Combs
*
* SPDX-License-Identifier: GPL-2.0-or-later
*
* Ref
* GR-1299-CORE
*/

#include "config.h"

#include <epan/packet.h>
#include <epan/oids.h>
#include <epan/asn1.h>
#include <epan/expert.h>

#include "packet-ber.h"
#include "packet-ansi_tcap.h"

#if defined(__GNUC__)
/*
 * This is meant to handle dissect_ain_ROS' defined but not used.
 *
 * DIAG_OFF doesn't work with llvm-gcc, for some unknown reason, so
 * we just use the pragma directly.
 */
#pragma GCC diagnostic ignored "-Wunused-function"
#endif

#define PNAME  "Advanced Intelligent Network"
#define PSNAME "AIN"
#define PFNAME "ain"

void proto_register_ain(void);
void proto_reg_handoff_ain(void);


/* Initialize the protocol and registered fields */
static int proto_ain;

static dissector_handle_t   ain_handle;

/* include constants */
#define noInvokeId                     NULL

static int hf_ain_ext_type_oid;
static int hf_ain_odd_even_indicator;
static int hf_ain_nature_of_address;
static int hf_ain_numbering_plan;
static int hf_ain_bcd_digits;
static int hf_ain_carrier_selection;
static int hf_ain_nature_of_carrier;
static int hf_ain_nr_digits;
static int hf_ain_carrier_bcd_digits;
static int hf_ain_amaslpid;

static int hf_ain_CallInfoFromResourceArg_PDU;    /* CallInfoFromResourceArg */
static int hf_ain_CloseArg_PDU;                   /* CloseArg */
static int hf_ain_CTRClearArg_PDU;                /* CTRClearArg */
static int hf_ain_FailureOutcomeArg_PDU;          /* FailureOutcomeArg */
static int hf_ain_InfoAnalyzedArg_PDU;            /* InfoAnalyzedArg */
static int hf_ain_InfoCollectedArg_PDU;           /* InfoCollectedArg */
static int hf_ain_NetworkBusyArg_PDU;             /* NetworkBusyArg */
static int hf_ain_OAnswerArg_PDU;                 /* OAnswerArg */
static int hf_ain_OAbandonArg_PDU;                /* OAbandonArg */
static int hf_ain_ODisconnectArg_PDU;             /* ODisconnectArg */
static int hf_ain_OMidCallArg_PDU;                /* OMidCallArg */
static int hf_ain_ONoAnswerArg_PDU;               /* ONoAnswerArg */
static int hf_ain_OSuspendedArg_PDU;              /* OSuspendedArg */
static int hf_ain_OTermSeizedArg_PDU;             /* OTermSeizedArg */
static int hf_ain_OriginationAttemptArg_PDU;      /* OriginationAttemptArg */
static int hf_ain_ResourceClearArg_PDU;           /* ResourceClearArg */
static int hf_ain_RES_resourceClear_PDU;          /* RES_resourceClear */
static int hf_ain_SuccessOutcomeArg_PDU;          /* SuccessOutcomeArg */
static int hf_ain_TAnswerArg_PDU;                 /* TAnswerArg */
static int hf_ain_TBusyArg_PDU;                   /* TBusyArg */
static int hf_ain_TDisconnectArg_PDU;             /* TDisconnectArg */
static int hf_ain_TDTMFEnteredArg_PDU;            /* TDTMFEnteredArg */
static int hf_ain_TMidCallArg_PDU;                /* TMidCallArg */
static int hf_ain_TNoAnswerArg_PDU;               /* TNoAnswerArg */
static int hf_ain_TerminationAttemptArg_PDU;      /* TerminationAttemptArg */
static int hf_ain_TermResourceAvailableArg_PDU;   /* TermResourceAvailableArg */
static int hf_ain_TimeoutArg_PDU;                 /* TimeoutArg */
static int hf_ain_AnalyzeRouteArg_PDU;            /* AnalyzeRouteArg */
static int hf_ain_AuthorizeTerminationArg_PDU;    /* AuthorizeTerminationArg */
static int hf_ain_CancelResourceEventArg_PDU;     /* CancelResourceEventArg */
static int hf_ain_CollectInformationArg_PDU;      /* CollectInformationArg */
static int hf_ain_ConnectToResourceArg_PDU;       /* ConnectToResourceArg */
static int hf_ain_ContinueArg_PDU;                /* ContinueArg */
static int hf_ain_CreateCallArg_PDU;              /* CreateCallArg */
static int hf_ain_CreateCallRes_PDU;              /* CreateCallRes */
static int hf_ain_DisconnectArg_PDU;              /* DisconnectArg */
static int hf_ain_DisconnectLegArg_PDU;           /* DisconnectLegArg */
static int hf_ain_ForwardCallArg_PDU;             /* ForwardCallArg */
static int hf_ain_MergeCallArg_PDU;               /* MergeCallArg */
static int hf_ain_MoveLegArg_PDU;                 /* MoveLegArg */
static int hf_ain_OfferCallArg_PDU;               /* OfferCallArg */
static int hf_ain_OriginateCallArg_PDU;           /* OriginateCallArg */
static int hf_ain_ReconnectArg_PDU;               /* ReconnectArg */
static int hf_ain_SendToResourceArg_PDU;          /* SendToResourceArg */
static int hf_ain_RES_sendToResource_PDU;         /* RES_sendToResource */
static int hf_ain_SetTimerArg_PDU;                /* SetTimerArg */
static int hf_ain_TimerUpdated_PDU;               /* TimerUpdated */
static int hf_ain_SplitLegArg_PDU;                /* SplitLegArg */
static int hf_ain_AcgArg_PDU;                     /* AcgArg */
static int hf_ain_AcgGlobalCtrlRestoreArg_PDU;    /* AcgGlobalCtrlRestoreArg */
static int hf_ain_RES_acgGlobalCtrlRestore_PDU;   /* RES_acgGlobalCtrlRestore */
static int hf_ain_AcgOverflowArg_PDU;             /* AcgOverflowArg */
static int hf_ain_ActivityTestArg_PDU;            /* ActivityTestArg */
static int hf_ain_RES_activityTest_PDU;           /* RES_activityTest */
static int hf_ain_CallTypeRequestArg_PDU;         /* CallTypeRequestArg */
static int hf_ain_RES_callTypeRequest_PDU;        /* RES_callTypeRequest */
static int hf_ain_ControlRequestArg_PDU;          /* ControlRequestArg */
static int hf_ain_EchoRequestArg_PDU;             /* EchoRequestArg */
static int hf_ain_RES_echoRequest_PDU;            /* RES_echoRequest */
static int hf_ain_FurnishAMAInformationArg_PDU;   /* FurnishAMAInformationArg */
static int hf_ain_MonitorForChangeArg_PDU;        /* MonitorForChangeArg */
static int hf_ain_MonitorSuccessArg_PDU;          /* MonitorSuccessArg */
static int hf_ain_NCADataArg_PDU;                 /* NCADataArg */
static int hf_ain_NCARequestArg_PDU;              /* NCARequestArg */
static int hf_ain_RES_nCARequest_PDU;             /* RES_nCARequest */
static int hf_ain_QueryRequestArg_PDU;            /* QueryRequestArg */
static int hf_ain_RES_queryRequest_PDU;           /* RES_queryRequest */
static int hf_ain_RequestReportBCMEventArg_PDU;   /* RequestReportBCMEventArg */
static int hf_ain_StatusReportedArg_PDU;          /* StatusReportedArg */
static int hf_ain_TerminationNotificationArg_PDU;  /* TerminationNotificationArg */
static int hf_ain_UpdateArg_PDU;                  /* UpdateArg */
static int hf_ain_RES_update_PDU;                 /* RES_update */
static int hf_ain_UpdateRequestArg_PDU;           /* UpdateRequestArg */
static int hf_ain_RES_updateRequest_PDU;          /* RES_updateRequest */
static int hf_ain_PAR_applicationError_PDU;       /* PAR_applicationError */
static int hf_ain_PAR_failureReport_PDU;          /* PAR_failureReport */
static int hf_ain_iPReturnBlock;                  /* IPReturnBlock */
static int hf_ain_amp1;                           /* Amp1 */
static int hf_ain_amp2;                           /* Amp2 */
static int hf_ain_extensionParameter;             /* ExtensionParameter */
static int hf_ain_userID;                         /* UserID */
static int hf_ain_bearerCapability;               /* BearerCapability */
static int hf_ain_closeCause;                     /* CloseCause */
static int hf_ain_clearCause;                     /* ClearCause */
static int hf_ain_legID;                          /* LegID */
static int hf_ain_ccID;                           /* CcID */
static int hf_ain_bCMType;                        /* BCMType */
static int hf_ain_pointInCall;                    /* PointInCall */
static int hf_ain_collectedDigits;                /* CollectedDigits */
static int hf_ain_collectedAddressInfo;           /* CollectedAddressInfo */
static int hf_ain_carrier;                        /* Carrier */
static int hf_ain_failureCause;                   /* FailureCause */
static int hf_ain_aMAMeasurement;                 /* AMAMeasurement */
static int hf_ain_clearCauseData;                 /* ClearCauseData */
static int hf_ain_notificationIndicator;          /* NotificationIndicator */
static int hf_ain_calledPartyID;                  /* CalledPartyID */
static int hf_ain_lata;                           /* Lata */
static int hf_ain_triggerCriteriaType;            /* TriggerCriteriaType */
static int hf_ain_chargeNumber;                   /* ChargeNumber */
static int hf_ain_callingPartyID;                 /* CallingPartyID */
static int hf_ain_callingPartyBGID;               /* CallingPartyBGID */
static int hf_ain_chargePartyStationType;         /* ChargePartyStationType */
static int hf_ain_accessCode;                     /* AccessCode */
static int hf_ain_verticalServiceCode;            /* VerticalServiceCode */
static int hf_ain_tcm;                            /* Tcm */
static int hf_ain_originalCalledPartyID;          /* OriginalCalledPartyID */
static int hf_ain_redirectingPartyID;             /* RedirectingPartyID */
static int hf_ain_redirectionInformation;         /* RedirectionInformation */
static int hf_ain_aCGEncountered;                 /* ACGEncountered */
static int hf_ain_sap;                            /* Sap */
static int hf_ain_sTRConnection;                  /* STRConnection */
static int hf_ain_aMASequenceNumber;              /* AMASequenceNumber */
static int hf_ain_genericAddressList;             /* GenericAddressList */
static int hf_ain_networkSpecificFacilities;      /* NetworkSpecificFacilities */
static int hf_ain_cTRConnection;                  /* CTRConnection */
static int hf_ain_jurisdictionInformation;        /* JurisdictionInformation */
static int hf_ain_prefix;                         /* Prefix */
static int hf_ain_callingGeodeticLocation;        /* CallingGeodeticLocation */
static int hf_ain_triggerInformation;             /* TriggerInformation */
static int hf_ain_disconnectCause;                /* DisconnectCause */
static int hf_ain_featureActivatorID;             /* FeatureActivatorID */
static int hf_ain_busyCause;                      /* BusyCause */
static int hf_ain_busyType;                       /* BusyType */
static int hf_ain_calledPartyStationType;         /* CalledPartyStationType */
static int hf_ain_genericName;                    /* GenericName */
static int hf_ain_dTMFDigitsDetected;             /* DTMFDigitsDetected */
static int hf_ain_rTPServiceIndicator;            /* RTPServiceIndicator */
static int hf_ain_outpulseNumber;                 /* OutpulseNumber */
static int hf_ain_primaryTrunkGroup;              /* PrimaryTrunkGroup */
static int hf_ain_alternateTrunkGroup;            /* AlternateTrunkGroup */
static int hf_ain_secondAlternateTrunkGroup;      /* SecondAlternateTrunkGroup */
static int hf_ain_alternateCarrier;               /* AlternateCarrier */
static int hf_ain_secondAlternateCarrier;         /* SecondAlternateCarrier */
static int hf_ain_passiveLegTreatment;            /* PassiveLegTreatment */
static int hf_ain_primaryBillingIndicator;        /* PrimaryBillingIndicator */
static int hf_ain_alternateBillingIndicator;      /* AlternateBillingIndicator */
static int hf_ain_secondAlternateBillingIndicator;  /* SecondAlternateBillingIndicator */
static int hf_ain_overflowBillingIndicator;       /* OverflowBillingIndicator */
static int hf_ain_aMAAlternateBillingNumber;      /* AMAAlternateBillingNumber */
static int hf_ain_aMABusinessCustomerID;          /* AMABusinessCustomerID */
static int hf_ain_aMALineNumberList;              /* SEQUENCE_SIZE_1_2_OF_AMALineNumber */
static int hf_ain_aMALineNumberList_item;         /* AMALineNumber */
static int hf_ain_aMAslpID;                       /* AMAslpID */
static int hf_ain_aMADigitsDialedWCList;          /* SEQUENCE_SIZE_1_5_OF_AMADigitsDialedWC */
static int hf_ain_aMADigitsDialedWCList_item;     /* AMADigitsDialedWC */
static int hf_ain_serviceProviderID;              /* ServiceProviderID */
static int hf_ain_serviceContext;                 /* ServiceContext */
static int hf_ain_aMABillingFeature;              /* AMABillingFeature */
static int hf_ain_carrierUsage;                   /* CarrierUsage */
static int hf_ain_forwardCallIndicator;           /* ForwardCallIndicator */
static int hf_ain_aMAServiceProviderID;           /* AMAServiceProviderID */
static int hf_ain_genericDigitsList;              /* GenericDigitsList */
static int hf_ain_applyRestrictions;              /* ApplyRestrictions */
static int hf_ain_displayText;                    /* DisplayText */
static int hf_ain_controllingLegTreatment;        /* ControllingLegTreatment */
static int hf_ain_aMAserviceProviderID;           /* AMAServiceProviderID */
static int hf_ain_dPConverter;                    /* DPConverter */
static int hf_ain_alternateDialingPlanInd;        /* AlternateDialingPlanInd */
static int hf_ain_resourceType;                   /* ResourceType */
static int hf_ain_strParameterBlock;              /* StrParameterBlock */
static int hf_ain_disconnectFlag;                 /* DisconnectFlag */
static int hf_ain_destinationAddress;             /* DestinationAddress */
static int hf_ain_aMAMeasure;                     /* AMAMeasure */
static int hf_ain_notificationDuration;           /* NotificationDuration */
static int hf_ain_wakeUpDuration;                 /* WakeUpDuration */
static int hf_ain_oSIIndicator;                   /* OSIIndicator */
static int hf_ain_rTPReroutingNumber;             /* RTPReroutingNumber */
static int hf_ain_csID;                           /* CsID */
static int hf_ain_lampTreatment;                  /* LampTreatment */
static int hf_ain_secondAlternatecarrier;         /* SecondAlternateCarrier */
static int hf_ain_answerIndicator;                /* AnswerIndicator */
static int hf_ain_extendedRinging;                /* ExtendedRinging */
static int hf_ain_tSTRCTimer;                     /* TSTRCTimer */
static int hf_ain_partyID;                        /* PartyID */
static int hf_ain_partyOnHold;                    /* PartyOnHold */
static int hf_ain_sSPResponseMessageTimerT1;      /* SSPResponseMessageTimerT1 */
static int hf_ain_controlCauseIndicator;          /* ControlCauseIndicator */
static int hf_ain_gapDuration;                    /* GapDuration */
static int hf_ain_gapInterval;                    /* GapInterval */
static int hf_ain_translationType;                /* TranslationType */
static int hf_ain_globalTitleAddress;             /* GlobalTitleAddress */
static int hf_ain_aCGGlobalOverride;              /* ACGGlobalOverride */
static int hf_ain_actResult;                      /* ActResult */
static int hf_ain_transID;                        /* TransID */
static int hf_ain_callType;                       /* CallType */
static int hf_ain_congestionLevel;                /* CongestionLevel */
static int hf_ain_ssignalingPointCode;            /* SignalingPointCode */
static int hf_ain_subsystemNumber;                /* SubsystemNumber */
static int hf_ain_applicationIndicator;           /* ApplicationIndicator */
static int hf_ain_aaMABAFModules;                 /* AMABAFModules */
static int hf_ain_aMASetHexABIndicator;           /* AMASetHexABIndicator */
static int hf_ain_facilityStatus;                 /* FacilityStatus */
static int hf_ain_monitorTime;                    /* MonitorTime */
static int hf_ain_facilityGID;                    /* FacilityGID */
static int hf_ain_facilityMemberID;               /* FacilityMemberID */
static int hf_ain_controlEncountered;             /* ControlEncountered */
static int hf_ain_id;                             /* T_id */
static int hf_ain_srhrGroupID;                    /* SrhrGroupID */
static int hf_ain_envelopeEncodingAuthority;      /* EnvelopeEncodingAuthority */
static int hf_ain_envelopContent;                 /* EnvelopContent */
static int hf_ain_securityEnvelope;               /* SecurityEnvelope */
static int hf_ain_infoProvided;                   /* InfoProvided */
static int hf_ain_provideInfo;                    /* ProvideInfo */
static int hf_ain_eDPRequest;                     /* EDPRequest */
static int hf_ain_eDPNotification;                /* EDPNotification */
static int hf_ain_oNoAnswerTimer;                 /* ONoAnswerTimer */
static int hf_ain_tNoAnswerTimer;                 /* TNoAnswerTimer */
static int hf_ain_timeoutTimer;                   /* TimeoutTimer */
static int hf_ain_oDTMFDigitsString;              /* ODTMFDigitsString */
static int hf_ain_oDTMFNumberOfDigits;            /* ODTMFNumberOfDigits */
static int hf_ain_tDTMFDigitString;               /* TDTMFDigitString */
static int hf_ain_tDTMFNumberOfDigits;            /* TDTMFNumberOfDigits */
static int hf_ain_statusCause;                    /* StatusCause */
static int hf_ain_echoData;                       /* EchoData */
static int hf_ain_terminationIndicator;           /* TerminationIndicator */
static int hf_ain_connectTime;                    /* ConnectTime */
static int hf_ain_resultCause;                    /* ResultCause */
static int hf_ain_administrableObject;            /* AdministrableObject */
static int hf_ain_editListType;                   /* EditListType */
static int hf_ain_triggerCriteriaFlag;            /* TriggerCriteriaFlag */
static int hf_ain_applicationErrorString;         /* ApplicationErrorString */
static int hf_ain_failureCauseData;               /* FailureCauseData */
static int hf_ain_triggerItemAssignment;          /* TriggerItemAssignment */
static int hf_ain_sSPUserResource;                /* SSPUserResource */
static int hf_ain_srhrGroup;                      /* SrhrGroup */
static int hf_ain_networkTestDesignator;          /* NetworkTestDesignator */
static int hf_ain_operationsMonitoringAssignment;  /* OperationsMonitoringAssignment */
static int hf_ain_sSPUserResourceID;              /* SSPUserResourceID */
static int hf_ain_triggerItemID;                  /* TriggerItemID */
static int hf_ain_activationStateCode;            /* ActivationStateCode */
static int hf_ain_potentialUse;                   /* PotentialUse */
static int hf_ain_sSPUserResourceSubID;           /* SSPUserResourceSubID */
static int hf_ain_dn;                             /* Dn */
static int hf_ain_dnCtID;                         /* DnCtID */
static int hf_ain_spid;                           /* Spid */
static int hf_ain_trunkGroupID;                   /* TrunkGroupID */
static int hf_ain_localSSPID;                     /* LocalSSPID */
static int hf_ain_publicDialingPlanID;            /* PublicDialingPlanID */
static int hf_ain_pRIOfficeEquipmentID;           /* PRIOfficeEquipmentID */
static int hf_ain_basicBusinessGroupID;           /* BasicBusinessGroupID */
static int hf_ain_basicBusinessGroupDialingPlanID;  /* BasicBusinessGroupDialingPlanID */
static int hf_ain_aFRPatternID;                   /* AFRPatternID */
static int hf_ain_officeEquipmentID;              /* OfficeEquipmentID */
static int hf_ain_ct;                             /* Ct */
static int hf_ain_dPNumber;                       /* DPNumber */
static int hf_ain_triggerItemSubnumber;           /* TriggerItemSubnumber */
static int hf_ain_iSDNBChannelID;                 /* ISDNBChannelID */
static int hf_ain_pRIDS1ID;                       /* PRIDS1ID */
static int hf_ain_pRIDS0ID;                       /* PRIDS0ID */
static int hf_ain_updateGroups;                   /* UpdateGroups */
static int hf_ain_cancelInterdigitTimer;          /* CancelInterdigitTimer */
static int hf_ain_updateGroup1;                   /* UpdateGroup1 */
static int hf_ain_updateGroup2;                   /* UpdateGroup2 */
static int hf_ain_updateGroup3;                   /* UpdateGroup3 */
static int hf_ain_updateGroup4;                   /* UpdateGroup4 */
static int hf_ain_updateGroup5;                   /* UpdateGroup5 */
static int hf_ain_updateGroup6;                   /* UpdateGroup6 */
static int hf_ain_updateGroup7;                   /* UpdateGroup7 */
static int hf_ain_updateGroup8;                   /* UpdateGroup8 */
static int hf_ain_updateGroup9;                   /* UpdateGroup9 */
static int hf_ain_service1;                       /* Service1 */
static int hf_ain_action1;                        /* Action1 */
static int hf_ain_service2;                       /* Service2 */
static int hf_ain_action2;                        /* Action2 */
static int hf_ain_delayInterval;                  /* DelayInterval */
static int hf_ain_service3;                       /* Service3 */
static int hf_ain_action3;                        /* Action3 */
static int hf_ain_editSpecificEntry;              /* EditSpecificEntry */
static int hf_ain_editAllEntries;                 /* EditAllEntries */
static int hf_ain_entry;                          /* Entry */
static int hf_ain_speedCallingCode;               /* SpeedCallingCode */
static int hf_ain_memorySlot;                     /* MemorySlot1 */
static int hf_ain_service4;                       /* Service4 */
static int hf_ain_action4;                        /* Action4 */
static int hf_ain_forwardingDn;                   /* ForwardingDn */
static int hf_ain_set;                            /* Set */
static int hf_ain_clear;                          /* Clear */
static int hf_ain_service5;                       /* Service5 */
static int hf_ain_action5;                        /* Action5 */
static int hf_ain_service6;                       /* Service6 */
static int hf_ain_action6;                        /* Action6 */
static int hf_ain_service7;                       /* Service7 */
static int hf_ain_action7;                        /* Action7 */
static int hf_ain_toggle;                         /* Toggle */
static int hf_ain_service8;                       /* Service8 */
static int hf_ain_action8;                        /* Action8 */
static int hf_ain_action8_invoke;                 /* Invoke8 */
static int hf_ain_service9;                       /* Service9 */
static int hf_ain_action9;                        /* Action9 */
static int hf_ain_changeList;                     /* ChangeList */
static int hf_ain_srhrID;                         /* SrhrID */
static int hf_ain_ntdID;                          /* NtdID */
static int hf_ain_ntdIndirectID;                  /* NtdIndirectID */
static int hf_ain_operationsMonitoredItemID;      /* OperationsMonitoredItemID */
static int hf_ain_aMATimeDuration;                /* AMATimeDuration */
static int hf_ain_aMATimeGuard;                   /* AMATimeGuard */
static int hf_ain_ampAINNodeID;                   /* AmpAINNodeID */
static int hf_ain_ampCLogSeqNo;                   /* AmpCLogSeqNo */
static int hf_ain_ampCLogRepInd;                  /* AmpCLogRepInd */
static int hf_ain_ampCallProgInd;                 /* AmpCallProgInd */
static int hf_ain_ampTestReqInd;                  /* AmpTestReqInd */
static int hf_ain_ampCLogName;                    /* AmpCLogName */
static int hf_ain_ampSvcProvID;                   /* AmpSvcProvID */
static int hf_ain_spcID;                          /* SpcID */
static int hf_ain_iSDNDeviceID;                   /* ISDNDeviceID */
static int hf_ain_ocn;                            /* Ocn */
static int hf_ain_errorCause;                     /* ErrorCause */
static int hf_ain_failedMessage;                  /* FailedMessage */
static int hf_ain__untag_item;                    /* DisplayInformation */
static int hf_ain_blank;                          /* OCTET_STRING_SIZE_1_20 */
static int hf_ain_skip;                           /* OCTET_STRING_SIZE_1_20 */
static int hf_ain_continuation;                   /* OCTET_STRING_SIZE_1_20 */
static int hf_ain_calledAddress;                  /* OCTET_STRING_SIZE_1_20 */
static int hf_ain_cause;                          /* OCTET_STRING_SIZE_1_20 */
static int hf_ain_progressIndicator;              /* OCTET_STRING_SIZE_1_20 */
static int hf_ain_displayInformation_notificationIndicator;  /* OCTET_STRING_SIZE_1_20 */
static int hf_ain_prompt;                         /* OCTET_STRING_SIZE_1_20 */
static int hf_ain_accumulatedDigits;              /* OCTET_STRING_SIZE_1_20 */
static int hf_ain_status;                         /* OCTET_STRING_SIZE_1_20 */
static int hf_ain_inband;                         /* OCTET_STRING_SIZE_1_20 */
static int hf_ain_callingAddress;                 /* OCTET_STRING_SIZE_1_20 */
static int hf_ain_reason;                         /* OCTET_STRING_SIZE_1_20 */
static int hf_ain_callingPartyName;               /* OCTET_STRING_SIZE_1_20 */
static int hf_ain_calledPartyName;                /* OCTET_STRING_SIZE_1_20 */
static int hf_ain_originalCalledName;             /* OCTET_STRING_SIZE_1_20 */
static int hf_ain_redirectingName;                /* OCTET_STRING_SIZE_1_20 */
static int hf_ain_connectedName;                  /* OCTET_STRING_SIZE_1_20 */
static int hf_ain_origRestrictions;               /* OCTET_STRING_SIZE_1_20 */
static int hf_ain_dateTimeOfDay;                  /* OCTET_STRING_SIZE_1_20 */
static int hf_ain_callAppearanceID;               /* OCTET_STRING_SIZE_1_20 */
static int hf_ain_featureAddress;                 /* OCTET_STRING_SIZE_1_20 */
static int hf_ain_redirectionName;                /* OCTET_STRING_SIZE_1_20 */
static int hf_ain_redirectionNumber;              /* OCTET_STRING_SIZE_1_20 */
static int hf_ain_redirectingNumber;              /* OCTET_STRING_SIZE_1_20 */
static int hf_ain_originalCalledNumber;           /* OCTET_STRING_SIZE_1_20 */
static int hf_ain_connectedNumber;                /* OCTET_STRING_SIZE_1_20 */
static int hf_ain_text;                           /* OCTET_STRING_SIZE_1_20 */
static int hf_ain_redirectingReason;              /* OCTET_STRING_SIZE_1_20 */
static int hf_ain_assignmentAuthority;            /* T_assignmentAuthority */
static int hf_ain_parameters;                     /* T_parameters */
static int hf_ain_mlhg;                           /* Mlhg */
static int hf_ain_opCode;                         /* INTEGER */
static int hf_ain_parameter;                      /* OCTET_STRING */
static int hf_ain_invParms;                       /* InvParms */
static int hf_ain_InvParms_item;                  /* Parms */
static int hf_ain_oDTMFNumberofDigits;            /* ODTMFNumberOfDigits */
static int hf_ain_timerUpdated;                   /* TimerUpdated */
static int hf_ain_derviceProviderID;              /* ServiceProviderID */
static int hf_ain_aMABAFModules;                  /* AMABAFModules */
static int hf_ain_aMALineNumber;                  /* AMALineNumber */
static int hf_ain_aMADigitsDialedWC;              /* AMADigitsDialedWC */
static int hf_ain_genericAddress;                 /* GenericAddress */
static int hf_ain_signalingPointCode;             /* SignalingPointCode */
static int hf_ain_nationalGapInterval;            /* NationalGapInterval */
static int hf_ain_privateGapInterval;             /* PrivateGapInterval */
static int hf_ain__untag_item_01;                 /* GenericAddress */
static int hf_ain__untag_item_02;                 /* GenericDigits */
static int hf_ain_entireList;                     /* EntireList */
static int hf_ain_memorySlot_01;                  /* MemorySlot */
static int hf_ain_listSize;                       /* ListSize */
static int hf_ain_forwardToDn;                    /* ForwardToDn */
static int hf_ain_empty;                          /* Empty */
static int hf_ain_EntireList_item;                /* Entry2 */
static int hf_ain_privateDn;                      /* PrivateDn */
static int hf_ain_incoming;                       /* Incoming */
static int hf_ain_outgoing;                       /* Outgoing */
static int hf_ain_aINDigits;                      /* AINDigits */
static int hf_ain_timestamp;                      /* Timestamp */
static int hf_ain_requestGroups;                  /* RequestGroups */
static int hf_ain_requestMemorySlot;              /* RequestMemorySlot */
static int hf_ain_requestGroup1;                  /* RequestGroup1 */
static int hf_ain_requestGroup2;                  /* RequestGroup2 */
static int hf_ain_requestGroup3;                  /* RequestGroup3 */
static int hf_ain_requestGroup4;                  /* RequestGroup4 */
static int hf_ain_requestGroup5;                  /* RequestGroup5 */
static int hf_ain_requestGroup6;                  /* RequestGroup6 */
static int hf_ain_request1;                       /* Request1 */
static int hf_ain_request2;                       /* Request2 */
static int hf_ain_request3;                       /* Request3 */
static int hf_ain_request4;                       /* Request4 */
static int hf_ain_request5;                       /* Request5 */
static int hf_ain_request6;                       /* Request6 */
static int hf_ain_msrID;                          /* MsrID */
static int hf_ain_announcementBlock;              /* AnnouncementBlock */
static int hf_ain_announcementDigitBlock;         /* AnnouncementDigitBlock */
static int hf_ain_flexParameterBlock;             /* FlexParameterBlock */
static int hf_ain_uninterAnnounceBlock;           /* UninterAnnounceBlock */
static int hf_ain_interAnnounceBlock;             /* InterAnnounceBlock */
static int hf_ain_UninterAnnounceBlock_item;      /* AnnounceElement */
static int hf_ain_InterAnnounceBlock_item;        /* AnnounceElement */
static int hf_ain_maximumDigits;                  /* MaximumDigits */
static int hf_ain_intervalTime;                   /* IntervalTime */
static int hf_ain_localSSPTime;                   /* LocalSSPTime */
static int hf_ain_absoluteSCPTime;                /* AbsoluteSCPTime */
static int hf_ain_bri;                            /* T_bri */
static int hf_ain_privateFacilityGID;             /* PrivateFacilityGID */
static int hf_ain_aDSIcpeID;                      /* ADSIcpeID */
static int hf_ain_local;                          /* T_local */
static int hf_ain_global;                         /* OBJECT_IDENTIFIER */
static int hf_ain_invoke;                         /* Invoke */
static int hf_ain_returnResult;                   /* ReturnResult */
static int hf_ain_returnError;                    /* ReturnError */
static int hf_ain_reject;                         /* Reject */
static int hf_ain_invokeId;                       /* InvokeId */
static int hf_ain_linkedId;                       /* T_linkedId */
static int hf_ain_present;                        /* T_present */
static int hf_ain_absent;                         /* NULL */
static int hf_ain_opcode;                         /* Code */
static int hf_ain_argument;                       /* T_argument */
static int hf_ain_result;                         /* T_result */
static int hf_ain_result_01;                      /* T_result_01 */
static int hf_ain_errcode;                        /* Code */
static int hf_ain_parameter_01;                   /* T_parameter */
static int hf_ain_problem;                        /* T_problem */
static int hf_ain_general;                        /* GeneralProblem */
static int hf_ain_invokeproblem;                  /* InvokeProblem */
static int hf_ain_returnResult_01;                /* ReturnResultProblem */
static int hf_ain_returnError_01;                 /* ReturnErrorProblem */
static int hf_ain_present_01;                     /* INTEGER */
static int hf_ain_InvokeId_present;               /* InvokeId_present */
/* named bits */
static int hf_ain_ApplyRestrictions_U_code;
static int hf_ain_ApplyRestrictions_U_toll;
static int hf_ain_EDPNotification_U_oCalledPartyBusy;
static int hf_ain_EDPNotification_U_oNoAnswer;
static int hf_ain_EDPNotification_U_oTermSeized;
static int hf_ain_EDPNotification_U_oAnswer;
static int hf_ain_EDPNotification_U_tBusy;
static int hf_ain_EDPNotification_U_tNoAnswer;
static int hf_ain_EDPNotification_U_termResourceAvailable;
static int hf_ain_EDPNotification_U_tAnswer;
static int hf_ain_EDPNotification_U_networkBusy;
static int hf_ain_EDPNotification_U_oSuspended;
static int hf_ain_EDPNotification_U_oDisconnectCalled;
static int hf_ain_EDPNotification_U_oDisconnect;
static int hf_ain_EDPNotification_U_oAbandon;
static int hf_ain_EDPNotification_U_featureActivator;
static int hf_ain_EDPNotification_U_switchHookFlash;
static int hf_ain_EDPNotification_U_success;
static int hf_ain_EDPNotification_U_tDisconnect;
static int hf_ain_EDPNotification_U_timeout;
static int hf_ain_EDPNotification_U_originationAttempt;
static int hf_ain_EDPNotification_U_oDTMFEntered;
static int hf_ain_EDPNotification_U_tDTMFEntered;
static int hf_ain_EDPRequest_U_oCalledPartyBusy;
static int hf_ain_EDPRequest_U_oNoAnswer;
static int hf_ain_EDPRequest_U_oTermSeized;
static int hf_ain_EDPRequest_U_oAnswer;
static int hf_ain_EDPRequest_U_tBusy;
static int hf_ain_EDPRequest_U_tNoAnswer;
static int hf_ain_EDPRequest_U_termResourceAvailable;
static int hf_ain_EDPRequest_U_tAnswer;
static int hf_ain_EDPRequest_U_networkBusy;
static int hf_ain_EDPRequest_U_oSuspended;
static int hf_ain_EDPRequest_U_oDisconnectCalled;
static int hf_ain_EDPRequest_U_oDisconnect;
static int hf_ain_EDPRequest_U_oAbandon;
static int hf_ain_EDPRequest_U_featureActivator;
static int hf_ain_EDPRequest_U_switchHookFlash;
static int hf_ain_EDPRequest_U_success;
static int hf_ain_EDPRequest_U_tDisconnect;
static int hf_ain_EDPRequest_U_timeout;
static int hf_ain_EDPRequest_U_originationAttempt;
static int hf_ain_EDPRequest_U_oDTMFEntered;
static int hf_ain_EDPRequest_U_tDTMFEntered;
static int hf_ain_Empty_entireList;
static int hf_ain_Empty_outgoingmemorySlot;
static int hf_ain_Empty_incomingmemorySlot;
static int hf_ain_Empty_forwardToDn;
static int hf_ain_Request1_activationStatus;
static int hf_ain_Request2_activationStatus;
static int hf_ain_Request2_delayInterval;
static int hf_ain_Request3_activationStatus;
static int hf_ain_Request3_entireList;
static int hf_ain_Request3_listSize;
static int hf_ain_Request4_activationStatus;
static int hf_ain_Request4_forwardingDn;
static int hf_ain_Request5_activationStatus;
static int hf_ain_Request5_forwardingDn;
static int hf_ain_Request5_entireList;
static int hf_ain_Request5_listSize;
static int hf_ain_Request6_delayInterval;
static int hf_ain_RequestMemorySlot_incoming;
static int hf_ain_RequestMemorySlot_outgoing;

/* Initialize the subtree pointers */
static int ett_ain;
static int ett_ain_digits;
static int ett_ain_carrierformat;
static int ett_ain_amaslpid;

static int ett_ain_CallInfoFromResourceArg;
static int ett_ain_CloseArg;
static int ett_ain_CTRClearArg;
static int ett_ain_FailureOutcomeArg;
static int ett_ain_InfoAnalyzedArg;
static int ett_ain_InfoCollectedArg;
static int ett_ain_NetworkBusyArg;
static int ett_ain_OAnswerArg;
static int ett_ain_OAbandonArg;
static int ett_ain_ODisconnectArg;
static int ett_ain_OMidCallArg;
static int ett_ain_ONoAnswerArg;
static int ett_ain_OSuspendedArg;
static int ett_ain_OTermSeizedArg;
static int ett_ain_OriginationAttemptArg;
static int ett_ain_RES_resourceClear;
static int ett_ain_ResourceClearArg;
static int ett_ain_SuccessOutcomeArg;
static int ett_ain_TAnswerArg;
static int ett_ain_TBusyArg;
static int ett_ain_TDisconnectArg;
static int ett_ain_TDTMFEnteredArg;
static int ett_ain_TMidCallArg;
static int ett_ain_TNoAnswerArg;
static int ett_ain_TerminationAttemptArg;
static int ett_ain_TermResourceAvailableArg;
static int ett_ain_TimeoutArg;
static int ett_ain_AnalyzeRouteArg;
static int ett_ain_SEQUENCE_SIZE_1_2_OF_AMALineNumber;
static int ett_ain_SEQUENCE_SIZE_1_5_OF_AMADigitsDialedWC;
static int ett_ain_AuthorizeTerminationArg;
static int ett_ain_CancelResourceEventArg;
static int ett_ain_CollectInformationArg;
static int ett_ain_ConnectToResourceArg;
static int ett_ain_ContinueArg;
static int ett_ain_CreateCallArg;
static int ett_ain_CreateCallRes;
static int ett_ain_DisconnectArg;
static int ett_ain_DisconnectLegArg;
static int ett_ain_ForwardCallArg;
static int ett_ain_MergeCallArg;
static int ett_ain_MoveLegArg;
static int ett_ain_OfferCallArg;
static int ett_ain_OriginateCallArg;
static int ett_ain_ReconnectArg;
static int ett_ain_RES_sendToResource;
static int ett_ain_SendToResourceArg;
static int ett_ain_SetTimerArg;
static int ett_ain_SplitLegArg;
static int ett_ain_AcgArg;
static int ett_ain_RES_acgGlobalCtrlRestore;
static int ett_ain_AcgGlobalCtrlRestoreArg;
static int ett_ain_AcgOverflowArg;
static int ett_ain_RES_activityTest;
static int ett_ain_ActivityTestArg;
static int ett_ain_RES_callTypeRequest;
static int ett_ain_CallTypeRequestArg;
static int ett_ain_ControlRequestArg;
static int ett_ain_RES_echoRequest;
static int ett_ain_EchoRequestArg;
static int ett_ain_FurnishAMAInformationArg;
static int ett_ain_MonitorForChangeArg;
static int ett_ain_MonitorSuccessArg;
static int ett_ain_NCADataArg;
static int ett_ain_T_id;
static int ett_ain_RES_nCARequest;
static int ett_ain_NCARequestArg;
static int ett_ain_RES_queryRequest;
static int ett_ain_QueryRequestArg;
static int ett_ain_RequestReportBCMEventArg;
static int ett_ain_StatusReportedArg;
static int ett_ain_TerminationNotificationArg;
static int ett_ain_RES_update;
static int ett_ain_UpdateArg;
static int ett_ain_RES_updateRequest;
static int ett_ain_UpdateRequestArg;
static int ett_ain_PAR_applicationError;
static int ett_ain_PAR_failureReport;
static int ett_ain_AdministrableObject;
static int ett_ain_TriggerItemAssignment_U;
static int ett_ain_SSPUserResourceID;
static int ett_ain_DnCtID;
static int ett_ain_TriggerItemID;
static int ett_ain_SSPUserResourceSubID;
static int ett_ain_ISDNBChannelID;
static int ett_ain_SSPUserResource_U;
static int ett_ain_UpdateGroups;
static int ett_ain_UpdateGroup1;
static int ett_ain_Action1;
static int ett_ain_UpdateGroup2;
static int ett_ain_Action2;
static int ett_ain_UpdateGroup3;
static int ett_ain_Action3;
static int ett_ain_EditSpecificEntry;
static int ett_ain_Entry;
static int ett_ain_UpdateGroup4;
static int ett_ain_Action4;
static int ett_ain_ForwardingDn;
static int ett_ain_Set;
static int ett_ain_UpdateGroup5;
static int ett_ain_Action5;
static int ett_ain_UpdateGroup6;
static int ett_ain_Action6;
static int ett_ain_UpdateGroup7;
static int ett_ain_Action7;
static int ett_ain_UpdateGroup8;
static int ett_ain_Action8;
static int ett_ain_UpdateGroup9;
static int ett_ain_Action9;
static int ett_ain_ChangeList;
static int ett_ain_SrhrGroup_U;
static int ett_ain_NetworkTestDesignator_U;
static int ett_ain_NtdID;
static int ett_ain_OperationsMonitoringAssignment_U;
static int ett_ain_OperationsMonitoredItemID;
static int ett_ain_AMAMeasurement_U;
static int ett_ain_Amp2_U;
static int ett_ain_AmpAINNodeID;
static int ett_ain_AmpSvcProvID;
static int ett_ain_ApplicationErrorString_U;
static int ett_ain_ApplyRestrictions_U;
static int ett_ain_SEQUENCE_SIZE_1_15_OF_DisplayInformation;
static int ett_ain_DisplayInformation;
static int ett_ain_EDPNotification_U;
static int ett_ain_EDPRequest_U;
static int ett_ain_ExtensionParameter;
static int ett_ain_FacilityGID;
static int ett_ain_FailedMessage_U;
static int ett_ain_InvParms;
static int ett_ain_Parms;
static int ett_ain_GapInterval;
static int ett_ain_SEQUENCE_SIZE_1_5_OF_GenericAddress;
static int ett_ain_SEQUENCE_SIZE_1_5_OF_GenericDigits;
static int ett_ain_InfoProvided_U;
static int ett_ain_EntireList;
static int ett_ain_Entry2;
static int ett_ain_MemorySlot;
static int ett_ain_Incoming;
static int ett_ain_Outgoing;
static int ett_ain_Empty;
static int ett_ain_ProvideInfo_U;
static int ett_ain_RequestGroups;
static int ett_ain_RequestGroup1;
static int ett_ain_Request1;
static int ett_ain_RequestGroup2;
static int ett_ain_Request2;
static int ett_ain_RequestGroup3;
static int ett_ain_Request3;
static int ett_ain_RequestGroup4;
static int ett_ain_Request4;
static int ett_ain_RequestGroup5;
static int ett_ain_Request5;
static int ett_ain_RequestGroup6;
static int ett_ain_Request6;
static int ett_ain_RequestMemorySlot;
static int ett_ain_ServiceProviderID;
static int ett_ain_StrParameterBlock_U;
static int ett_ain_AnnouncementBlock;
static int ett_ain_UninterAnnounceBlock;
static int ett_ain_InterAnnounceBlock;
static int ett_ain_AnnouncementDigitBlock;
static int ett_ain_TimeoutTimer_U;
static int ett_ain_UserID_U;
static int ett_ain_T_bri;
static int ett_ain_Code;
static int ett_ain_ROS;
static int ett_ain_Invoke;
static int ett_ain_T_linkedId;
static int ett_ain_ReturnResult;
static int ett_ain_T_result;
static int ett_ain_ReturnError;
static int ett_ain_Reject;
static int ett_ain_T_problem;
static int ett_ain_InvokeId;

static expert_field ei_ain_unknown_invokeData;
static expert_field ei_ain_unknown_returnResultData;
static expert_field ei_ain_unknown_returnErrorData;

/* Global variables */
static uint32_t opcode;
static uint32_t errorCode;
//static const char *obj_id = NULL;

static int ain_opcode_type;
#define AIN_OPCODE_INVOKE        1
#define AIN_OPCODE_RETURN_RESULT 2
#define AIN_OPCODE_RETURN_ERROR  3
#define AIN_OPCODE_REJECT        4

/* Forward declarations */
static int dissect_invokeData(proto_tree *tree, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_);
static int dissect_returnResultData(proto_tree *tree, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_);
static int dissect_returnErrorData(proto_tree *tree, tvbuff_t *tvb, int offset, asn1_ctx_t *actx);

static const value_string ain_np_vals[] = {
    {   0, "Unknown or not applicable"},
    {   1, "ISDN Numbering Plan (ITU Rec. E.164)"},
    {   2, "Telephony Numbering (ITU-T Rec. E.164,E.163)"},
    {   3, "Data Numbering (ITU-T Rec. X.121)"},
    {   4, "Telex Numbering (ITU-T Rec. F.69)"},
    {   5, "Maritime Mobile Numbering"},
    {   6, "Land Mobile Numbering (ITU-T Rec. E.212)"},
    {   7, "Private Numbering Plan"},
    {   0, NULL }
};

static const value_string ain_carrier_selection_vals[] = {
    {   0, "No indication"},
    {   1, "Selected carrier identification code presubscribed and not input by calling party"},
    {   2, "Selected carrier identification code presubscribed and input by calling party"},
    {   3, "Selected carrier identification code presubscribed, no indication of whether input by calling party"},
    {   4, "Selected carrier identification code not presubscribed and input by calling party"},
    {   0, NULL }
};

static const value_string ain_nature_of_carrier_vals[] = {
    {   0, "No NOC Provided"},
    {   1, "local"},
    {   2, "intraLATA toll"},
    {   3, "interLATA"},
    {   4, "local, intraLATA toll and interLATA"},
    {   5, "local and intraLATA toll"},
    {   6, "intraLATA toll and interLATA"},
    {   0, NULL }
};


/* AIN OPERATIONS */
const value_string ain_opr_code_strings[] = {
  { 26116                                   , "callInfoFromResource" },
  { 28161                                   , "close" },
  { 26118                                   , "cTRClear" },
  { 25604                                   , "failureOutcome" },
  { 25603                                   , "infoAnalyzed" },
  { 25602                                   , "infoCollected" },
  { 25623                                   , "networkBusy" },
  { 25611                                   , "oAnswer" },
  { 25614                                   , "oAbandon" },
  { 25626                                   , "oDisconnect" },
  { 25615                                   , "oMidCall" },
  { 25609                                   , "oNoAnswer" },
  { 25625                                   , "oSuspended" },
  { 25612                                   , "oTermSeized" },
  { 25624                                   , "originationAttempt" },
  { 26114                                   , "resourceClear" },
  { 25617                                   , "successOutcome" },
  { 25610                                   , "tAnswer" },
  { 25606                                   , "tBusy" },
  { 25618                                   , "tDisconnect" },
  { 25628                                   , "tDTMFEntered" },
  { 25619                                   , "tMidCall" },
  { 25608                                   , "tNoAnswer" },
  { 25605                                   , "terminationAttempt" },
  { 25613                                   , "termResourceAvailable" },
  { 25620                                   , "timeout" },
  { 25857                                   , "analyzeRoute" },
  { 25858                                   , "authorizeTermination" },
  { 26115                                   , "cancelResourceEvent" },
  { 25861                                   , "collectInformation" },
  { 26117                                   , "connectToResource" },
  { 25869                                   , "continue" },
  { 25863                                   , "createCall" },
  { 25859                                   , "disconnect" },
  { 25864                                   , "disconnectLeg" },
  { 27137                                   , "forwardCall" },
  { 25865                                   , "mergeCall" },
  { 25866                                   , "moveLeg" },
  { 25860                                   , "offerCall" },
  { 25867                                   , "originateCall" },
  { 25870                                   , "reconnect" },
  { 26113                                   , "sendToResource" },
  { 26889                                   , "setTimer" },
  { 25868                                   , "splitLeg" },
  { 26881                                   , "acg" },
  { 26883                                   , "acgGlobalCtrlRestore" },
  { 26884                                   , "acgOverflow" },
  { 26886                                   , "activityTest" },
  { 26887                                   , "callTypeRequest" },
  { 26885                                   , "controlRequest" },
  { 26882                                   , "echoRequest" },
  { 27649                                   , "furnishAMAInformation" },
  { 26369                                   , "monitorForChange" },
  { 26371                                   , "monitorSuccess" },
  { 27394                                   , "nCAData" },
  { 27393                                   , "nCARequest" },
  { 26626                                   , "queryRequest" },
  { 27905                                   , "requestReportBCMEvent" },
  { 26370                                   , "statusReported" },
  { 26372                                   , "terminationNotification" },
  { 26627                                   , "update" },
  { 26625                                   , "updateRequest" },
  { 0, NULL }
};


/* AIN ERRORS */
static const value_string ain_err_code_string_vals[] = {
  { 1                                       , "applicationError" },
  { 2                                       , "failureReport" },
  { 0, NULL }
};




static int
dissect_ain_OCTET_STRING_SIZE_1_120(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_ain_IPReturnBlock(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 78, true, dissect_ain_OCTET_STRING_SIZE_1_120);

  return offset;
}



static int
dissect_ain_OCTET_STRING_SIZE_6(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_ain_Amp1(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 11, true, dissect_ain_OCTET_STRING_SIZE_6);

  return offset;
}



static int
dissect_ain_SpcID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_ain_AINDigits(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *parameter_tvb;
  proto_tree *subtree;

    offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &parameter_tvb);


  if (!parameter_tvb)
    return offset;

  subtree = proto_item_add_subtree(actx->created_item, ett_ain_digits);
  proto_tree_add_item(subtree, hf_ain_odd_even_indicator, parameter_tvb, 0, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(subtree, hf_ain_nature_of_address, parameter_tvb, 0, 1, ENC_BIG_ENDIAN);

  proto_tree_add_item(subtree, hf_ain_numbering_plan, parameter_tvb, 1, 1, ENC_BIG_ENDIAN);

  proto_tree_add_item(subtree, hf_ain_bcd_digits, parameter_tvb, 2, tvb_reported_length_remaining(parameter_tvb, 2), ENC_BCD_DIGITS_0_9|ENC_LITTLE_ENDIAN);


  return offset;
}



static int
dissect_ain_ISDNDeviceID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ain_AINDigits(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string ain_AmpAINNodeID_vals[] = {
  {   1, "spcID" },
  {   2, "iSDNDeviceID" },
  { 0, NULL }
};

static const ber_choice_t AmpAINNodeID_choice[] = {
  {   1, &hf_ain_spcID           , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ain_SpcID },
  {   2, &hf_ain_iSDNDeviceID    , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_ain_ISDNDeviceID },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_AmpAINNodeID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 AmpAINNodeID_choice, hf_index, ett_ain_AmpAINNodeID,
                                 NULL);

  return offset;
}



static int
dissect_ain_AmpCLogSeqNo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string ain_AmpCLogRepInd_vals[] = {
  {   0, "autoReportOS" },
  {   1, "requestReport" },
  {   2, "autoReportISDN" },
  { 0, NULL }
};


static int
dissect_ain_AmpCLogRepInd(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string ain_AmpCallProgInd_vals[] = {
  {   0, "callProgressVoiceAnnouncements" },
  {   1, "callProgressTextMessages" },
  { 0, NULL }
};


static int
dissect_ain_AmpCallProgInd(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_ain_AmpTestReqInd(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_ain_AmpCLogName(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_ain_IA5String_SIZE_4_8(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_ain_Ocn(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 87, true, dissect_ain_IA5String_SIZE_4_8);

  return offset;
}


static const value_string ain_AmpSvcProvID_vals[] = {
  {  87, "ocn" },
  { 0, NULL }
};

static const ber_choice_t AmpSvcProvID_choice[] = {
  {  87, &hf_ain_ocn             , BER_CLASS_CON, 87, BER_FLAGS_NOOWNTAG, dissect_ain_Ocn },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_AmpSvcProvID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 AmpSvcProvID_choice, hf_index, ett_ain_AmpSvcProvID,
                                 NULL);

  return offset;
}


static const ber_sequence_t Amp2_U_sequence[] = {
  { &hf_ain_ampAINNodeID    , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ain_AmpAINNodeID },
  { &hf_ain_ampCLogSeqNo    , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_AmpCLogSeqNo },
  { &hf_ain_ampCLogRepInd   , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_AmpCLogRepInd },
  { &hf_ain_ampCallProgInd  , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_AmpCallProgInd },
  { &hf_ain_ampTestReqInd   , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_AmpTestReqInd },
  { &hf_ain_ampCLogName     , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_AmpCLogName },
  { &hf_ain_ampSvcProvID    , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_ain_AmpSvcProvID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_Amp2_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Amp2_U_sequence, hf_index, ett_ain_Amp2_U);

  return offset;
}



static int
dissect_ain_Amp2(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 109, true, dissect_ain_Amp2_U);

  return offset;
}



static int
dissect_ain_T_assignmentAuthority(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_ain_ext_type_oid, &actx->external.direct_reference);

  return offset;
}



static int
dissect_ain_T_parameters(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset=call_ber_oid_callback(actx->external.direct_reference, tvb, offset, actx->pinfo, tree, NULL);


  return offset;
}


static const ber_sequence_t ExtensionParameter_sequence[] = {
  { &hf_ain_assignmentAuthority, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_ain_T_assignmentAuthority },
  { &hf_ain_parameters      , BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_ain_T_parameters },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_ExtensionParameter(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ExtensionParameter_sequence, hf_index, ett_ain_ExtensionParameter);

  return offset;
}


static const ber_sequence_t CallInfoFromResourceArg_sequence[] = {
  { &hf_ain_iPReturnBlock   , BER_CLASS_CON, 78, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_IPReturnBlock },
  { &hf_ain_amp1            , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp1 },
  { &hf_ain_amp2            , BER_CLASS_CON, 109, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp2 },
  { &hf_ain_extensionParameter, BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_ExtensionParameter },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_CallInfoFromResourceArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CallInfoFromResourceArg_sequence, hf_index, ett_ain_CallInfoFromResourceArg);

  return offset;
}



static int
dissect_ain_Dn(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_ain_OCTET_STRING_SIZE_3_20(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_ain_Spid(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 49, true, dissect_ain_OCTET_STRING_SIZE_3_20);

  return offset;
}


static const ber_sequence_t T_bri_sequence[] = {
  { &hf_ain_spid            , BER_CLASS_CON, 49, BER_FLAGS_NOOWNTAG, dissect_ain_Spid },
  { &hf_ain_dn              , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ain_Dn },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_T_bri(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_bri_sequence, hf_index, ett_ain_T_bri);

  return offset;
}



static int
dissect_ain_TrunkGroupID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_ain_PrivateFacilityGID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_ain_ADSIcpeID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string ain_UserID_U_vals[] = {
  {   0, "dn" },
  {   1, "bri" },
  {   2, "trunkGroupID" },
  {   3, "privateFacilityGID" },
  {   4, "aDSIcpeID" },
  { 0, NULL }
};

static const ber_choice_t UserID_U_choice[] = {
  {   0, &hf_ain_dn              , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ain_Dn },
  {   1, &hf_ain_bri             , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_ain_T_bri },
  {   2, &hf_ain_trunkGroupID    , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_ain_TrunkGroupID },
  {   3, &hf_ain_privateFacilityGID, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_ain_PrivateFacilityGID },
  {   4, &hf_ain_aDSIcpeID       , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ain_ADSIcpeID },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_UserID_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 UserID_U_choice, hf_index, ett_ain_UserID_U,
                                 NULL);

  return offset;
}



static int
dissect_ain_UserID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 53, true, dissect_ain_UserID_U);

  return offset;
}


static const value_string ain_BearerCapability_U_vals[] = {
  {   0, "speech" },
  {   1, "f31kHzaudio" },
  {   2, "f7kHzaudio" },
  {   3, "b56kbps" },
  {   4, "b64kbps" },
  {   5, "packetModeData" },
  {   6, "multiRate" },
  { 0, NULL }
};


static int
dissect_ain_BearerCapability_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_ain_BearerCapability(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 13, true, dissect_ain_BearerCapability_U);

  return offset;
}


static const value_string ain_CloseCause_U_vals[] = {
  {   0, "callTerminated" },
  {   1, "eDPsCompleted" },
  {   2, "unexpectedCommunication" },
  {   3, "calledPartyAnswered" },
  {   4, "callForwardedEDPsCompleted" },
  {   5, "newRequestedEvent" },
  { 0, NULL }
};


static int
dissect_ain_CloseCause_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_ain_CloseCause(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 72, true, dissect_ain_CloseCause_U);

  return offset;
}


static const ber_sequence_t CloseArg_sequence[] = {
  { &hf_ain_userID          , BER_CLASS_CON, 53, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_UserID },
  { &hf_ain_bearerCapability, BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_BearerCapability },
  { &hf_ain_closeCause      , BER_CLASS_CON, 72, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_CloseCause },
  { &hf_ain_amp1            , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp1 },
  { &hf_ain_amp2            , BER_CLASS_CON, 109, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp2 },
  { &hf_ain_extensionParameter, BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_ExtensionParameter },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_CloseArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CloseArg_sequence, hf_index, ett_ain_CloseArg);

  return offset;
}



static int
dissect_ain_INTEGER_0_255(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_ain_ClearCause(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 21, true, dissect_ain_INTEGER_0_255);

  return offset;
}



static int
dissect_ain_INTEGER_0_2(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_ain_LegID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 132, true, dissect_ain_INTEGER_0_2);

  return offset;
}


static const value_string ain_CcID_U_vals[] = {
  {   0, "null" },
  {   1, "originatingSetup" },
  {   2, "stable2Party" },
  {   3, "terminatingSetup" },
  {   4, "threePartySetup" },
  {   5, "threePartySetupComplement" },
  {   6, "partyOnHold" },
  {   7, "partyOnHoldComplement" },
  {   8, "callWaiting" },
  {   9, "callWaitingComplement" },
  {  10, "stableMParty" },
  {  11, "transfer" },
  {  12, "forward" },
  { 0, NULL }
};


static int
dissect_ain_CcID_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_ain_CcID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 133, true, dissect_ain_CcID_U);

  return offset;
}


static const value_string ain_BCMType_U_vals[] = {
  {   0, "oBcm" },
  {   1, "tBcm" },
  { 0, NULL }
};


static int
dissect_ain_BCMType_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_ain_BCMType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 134, true, dissect_ain_BCMType_U);

  return offset;
}


static const value_string ain_PointInCall_U_vals[] = {
  {   1, "oNull" },
  {   2, "authorizeOrigAttempt" },
  {   3, "collectInformation" },
  {   4, "analyzeInformation" },
  {   5, "selectRoute" },
  {   6, "authorizeCallSetup" },
  {   7, "sendCall" },
  {   8, "oAlerting" },
  {   9, "oActive" },
  {  10, "oSuspended" },
  {  11, "tNull" },
  {  12, "authorizeTermination" },
  {  13, "selectFacility" },
  {  14, "presentCall" },
  {  15, "tAlerting" },
  {  16, "tActive" },
  {  17, "tSuspended" },
  { 0, NULL }
};


static int
dissect_ain_PointInCall_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_ain_PointInCall(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 135, true, dissect_ain_PointInCall_U);

  return offset;
}



static int
dissect_ain_CollectedDigits(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 23, true, dissect_ain_AINDigits);

  return offset;
}



static int
dissect_ain_CollectedAddressInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 22, true, dissect_ain_AINDigits);

  return offset;
}



static int
dissect_ain_CarrierFormat(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *parameter_tvb;
  proto_tree *subtree;

    offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &parameter_tvb);


  if (!parameter_tvb)
    return offset;

  subtree = proto_item_add_subtree(actx->created_item, ett_ain_carrierformat);
  /* Carrier Selection */
  proto_tree_add_item(subtree, hf_ain_carrier_selection, parameter_tvb, 0, 1, ENC_BIG_ENDIAN);
  /*  Nature of Carrier Number of Digits (always 4 )*/
  proto_tree_add_item(subtree, hf_ain_nature_of_carrier, parameter_tvb, 1, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(subtree, hf_ain_nr_digits, parameter_tvb, 1, 1, ENC_BIG_ENDIAN);

  /* 2nd Digit 1st Digit .. */
  proto_tree_add_item(subtree, hf_ain_carrier_bcd_digits, parameter_tvb, 2, tvb_reported_length_remaining(parameter_tvb, 2), ENC_BCD_DIGITS_0_9|ENC_LITTLE_ENDIAN);


  return offset;
}



static int
dissect_ain_Carrier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 41, true, dissect_ain_CarrierFormat);

  return offset;
}


static const value_string ain_FailureCause_U_vals[] = {
  {   1, "rateTooHigh" },
  {   2, "unavailableResources" },
  {   3, "apTimeout" },
  {   4, "apBusy" },
  {  13, "channelsBusy" },
  {  14, "abort" },
  {  15, "resourceLimitation" },
  {  16, "applicationError" },
  {  17, "securityError" },
  {  18, "protocolError" },
  {  19, "timerExpired" },
  {  20, "temporaryFailure" },
  {  21, "msridDoesNotMatchUserProfile" },
  {  22, "segmentationError" },
  {  23, "ncasDisallowed" },
  {  24, "controlEncountered" },
  {  25, "improperCoding" },
  {  26, "inappropriateCondition" },
  {  27, "inappropriateUserInterface" },
  {  28, "inappropriateLegManipulation" },
  {  29, "callingInterfaceBusy" },
  { 0, NULL }
};


static int
dissect_ain_FailureCause_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_ain_FailureCause(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 32, true, dissect_ain_FailureCause_U);

  return offset;
}



static int
dissect_ain_AMATimeDuration(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string ain_AMATimeGuard_vals[] = {
  {   0, "noTimingGuard" },
  {   1, "timingGuardExists" },
  { 0, NULL }
};


static int
dissect_ain_AMATimeGuard(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t AMAMeasurement_U_sequence[] = {
  { &hf_ain_aMATimeDuration , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ain_AMATimeDuration },
  { &hf_ain_aMATimeGuard    , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ain_AMATimeGuard },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_AMAMeasurement_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AMAMeasurement_U_sequence, hf_index, ett_ain_AMAMeasurement_U);

  return offset;
}



static int
dissect_ain_AMAMeasurement(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 73, true, dissect_ain_AMAMeasurement_U);

  return offset;
}



static int
dissect_ain_OCTET_STRING_SIZE_1_20(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_ain_ClearCauseData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 74, true, dissect_ain_OCTET_STRING_SIZE_1_20);

  return offset;
}


static const ber_sequence_t CTRClearArg_sequence[] = {
  { &hf_ain_clearCause      , BER_CLASS_CON, 21, BER_FLAGS_NOOWNTAG, dissect_ain_ClearCause },
  { &hf_ain_legID           , BER_CLASS_CON, 132, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_LegID },
  { &hf_ain_ccID            , BER_CLASS_CON, 133, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_CcID },
  { &hf_ain_bCMType         , BER_CLASS_CON, 134, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_BCMType },
  { &hf_ain_pointInCall     , BER_CLASS_CON, 135, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_PointInCall },
  { &hf_ain_collectedDigits , BER_CLASS_CON, 23, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_CollectedDigits },
  { &hf_ain_collectedAddressInfo, BER_CLASS_CON, 22, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_CollectedAddressInfo },
  { &hf_ain_carrier         , BER_CLASS_CON, 41, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Carrier },
  { &hf_ain_failureCause    , BER_CLASS_CON, 32, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_FailureCause },
  { &hf_ain_amp1            , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp1 },
  { &hf_ain_amp2            , BER_CLASS_CON, 109, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp2 },
  { &hf_ain_aMAMeasurement  , BER_CLASS_CON, 73, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AMAMeasurement },
  { &hf_ain_clearCauseData  , BER_CLASS_CON, 74, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ClearCauseData },
  { &hf_ain_iPReturnBlock   , BER_CLASS_CON, 78, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_IPReturnBlock },
  { &hf_ain_extensionParameter, BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_ExtensionParameter },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_CTRClearArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CTRClearArg_sequence, hf_index, ett_ain_CTRClearArg);

  return offset;
}



static int
dissect_ain_NotificationIndicator(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const ber_sequence_t FailureOutcomeArg_sequence[] = {
  { &hf_ain_userID          , BER_CLASS_CON, 53, BER_FLAGS_NOOWNTAG, dissect_ain_UserID },
  { &hf_ain_bearerCapability, BER_CLASS_CON, 13, BER_FLAGS_NOOWNTAG, dissect_ain_BearerCapability },
  { &hf_ain_notificationIndicator, BER_CLASS_CON, 111, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_NotificationIndicator },
  { &hf_ain_ccID            , BER_CLASS_CON, 133, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_CcID },
  { &hf_ain_legID           , BER_CLASS_CON, 132, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_LegID },
  { &hf_ain_bCMType         , BER_CLASS_CON, 134, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_BCMType },
  { &hf_ain_pointInCall     , BER_CLASS_CON, 135, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_PointInCall },
  { &hf_ain_failureCause    , BER_CLASS_CON, 32, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_FailureCause },
  { &hf_ain_amp1            , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp1 },
  { &hf_ain_amp2            , BER_CLASS_CON, 109, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp2 },
  { &hf_ain_extensionParameter, BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_ExtensionParameter },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_FailureOutcomeArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   FailureOutcomeArg_sequence, hf_index, ett_ain_FailureOutcomeArg);

  return offset;
}



static int
dissect_ain_CalledPartyID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 15, true, dissect_ain_AINDigits);

  return offset;
}



static int
dissect_ain_Lata(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 35, true, dissect_ain_AINDigits);

  return offset;
}


static const value_string ain_TriggerCriteriaType_U_vals[] = {
  {   0, "featureActivator" },
  {   1, "verticalServiceCode" },
  {   2, "customizedAccess" },
  {   3, "customizedIntercom" },
  {   4, "npa" },
  {   5, "npaNXX" },
  {   6, "nxx" },
  {   7, "nxxXXXX" },
  {   8, "npaNXXXXXX" },
  {   9, "countryCodeNPANXXXXXX" },
  {  10, "carrierAccess" },
  {  11, "prefixes" },
  {  12, "n11" },
  {  13, "aFR" },
  {  14, "sharedIOTrunk" },
  {  15, "terminationAttempt" },
  {  16, "offHookImmediate" },
  {  17, "offHookDelay" },
  {  18, "channelSetupPRI" },
  {  19, "npaN" },
  {  20, "npaNX" },
  {  21, "npaNXXX" },
  {  22, "npaNXXXX" },
  {  23, "npaNXXXXX" },
  {  24, "networkBusy" },
  {  25, "tNoAnswer" },
  {  26, "tBusy" },
  {  27, "oCalledPartyBusy" },
  {  28, "specificFeatureCode" },
  {  29, "oNoAnswer" },
  {  30, "priNetworkServices" },
  {  31, "oSwitchHookFlashImmediate" },
  {  32, "oFeatureActivator" },
  {  33, "oSwitchHookFlashSpecifiedCode" },
  {  34, "tSwitchHookFlashImmediate" },
  {  35, "tFeatureActivator" },
  {  36, "tSwitchHookFlashSpecifiedCode" },
  {  37, "numberPortability" },
  {  38, "onePlus" },
  {  39, "specifiedCarrier" },
  {  40, "international" },
  {  41, "zeroPlus" },
  {  42, "zeroMinus" },
  {  43, "localNumberPortabilityPORC" },
  {  44, "localNumberPortabilityPORCdonor" },
  {  45, "reserved" },
  {  46, "termResourceAvailable" },
  {  47, "officePublicFeatureCode" },
  {  48, "trunkGroup" },
  {  49, "dedicatedTrunkGroup" },
  {  50, "reserved" },
  { 0, NULL }
};


static int
dissect_ain_TriggerCriteriaType_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_ain_TriggerCriteriaType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 52, true, dissect_ain_TriggerCriteriaType_U);

  return offset;
}



static int
dissect_ain_ChargeNumber(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 19, true, dissect_ain_AINDigits);

  return offset;
}



static int
dissect_ain_CallingPartyID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 18, true, dissect_ain_AINDigits);

  return offset;
}



static int
dissect_ain_BusinessGroup(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_ain_CallingPartyBGID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 17, true, dissect_ain_BusinessGroup);

  return offset;
}



static int
dissect_ain_INTEGER_0_99(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_ain_ChargePartyStationType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 20, true, dissect_ain_INTEGER_0_99);

  return offset;
}



static int
dissect_ain_AccessCode(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 1, true, dissect_ain_AINDigits);

  return offset;
}



static int
dissect_ain_VerticalServiceCode(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 54, true, dissect_ain_AINDigits);

  return offset;
}



static int
dissect_ain_Tcm(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 51, true, dissect_ain_AINDigits);

  return offset;
}



static int
dissect_ain_OriginalCalledPartyID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 36, true, dissect_ain_AINDigits);

  return offset;
}



static int
dissect_ain_RedirectingPartyID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 43, true, dissect_ain_AINDigits);

  return offset;
}



static int
dissect_ain_OCTET_STRING_SIZE_2(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_ain_RedirectionInformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 44, true, dissect_ain_OCTET_STRING_SIZE_2);

  return offset;
}



static int
dissect_ain_OCTET_STRING_SIZE_1(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_ain_ACGEncountered(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 2, true, dissect_ain_OCTET_STRING_SIZE_1);

  return offset;
}



static int
dissect_ain_OCTET_STRING_SIZE_1_10(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_ain_Sap(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 81, true, dissect_ain_OCTET_STRING_SIZE_1_10);

  return offset;
}



static int
dissect_ain_BOOLEAN(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_ain_STRConnection(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 96, true, dissect_ain_BOOLEAN);

  return offset;
}



static int
dissect_ain_AMASequenceNumber(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 89, true, dissect_ain_OCTET_STRING_SIZE_2);

  return offset;
}



static int
dissect_ain_OCTET_STRING_SIZE_4_11(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_ain_GenericAddress(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 80, true, dissect_ain_OCTET_STRING_SIZE_4_11);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_5_OF_GenericAddress_sequence_of[1] = {
  { &hf_ain__untag_item_01  , BER_CLASS_CON, 80, BER_FLAGS_NOOWNTAG, dissect_ain_GenericAddress },
};

static int
dissect_ain_SEQUENCE_SIZE_1_5_OF_GenericAddress(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_SIZE_1_5_OF_GenericAddress_sequence_of, hf_index, ett_ain_SEQUENCE_SIZE_1_5_OF_GenericAddress);

  return offset;
}



static int
dissect_ain_GenericAddressList(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 107, true, dissect_ain_SEQUENCE_SIZE_1_5_OF_GenericAddress);

  return offset;
}



static int
dissect_ain_OCTET_STRING_SIZE_2_12(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_ain_NetworkSpecificFacilities(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 108, true, dissect_ain_OCTET_STRING_SIZE_2_12);

  return offset;
}



static int
dissect_ain_CTRConnection(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 141, true, dissect_ain_BOOLEAN);

  return offset;
}



static int
dissect_ain_OCTET_STRING_SIZE_3(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_ain_JurisdictionInformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 147, true, dissect_ain_OCTET_STRING_SIZE_3);

  return offset;
}


static const value_string ain_Prefix_U_vals[] = {
  {   0, "onePlus" },
  { 0, NULL }
};


static int
dissect_ain_Prefix_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_ain_Prefix(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 148, true, dissect_ain_Prefix_U);

  return offset;
}



static int
dissect_ain_OCTET_STRING_SIZE_8_13(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_ain_CallingGeodeticLocation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 162, true, dissect_ain_OCTET_STRING_SIZE_8_13);

  return offset;
}



static int
dissect_ain_TriggerInformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t InfoAnalyzedArg_sequence[] = {
  { &hf_ain_userID          , BER_CLASS_CON, 53, BER_FLAGS_NOOWNTAG, dissect_ain_UserID },
  { &hf_ain_bearerCapability, BER_CLASS_CON, 13, BER_FLAGS_NOOWNTAG, dissect_ain_BearerCapability },
  { &hf_ain_calledPartyID   , BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_CalledPartyID },
  { &hf_ain_lata            , BER_CLASS_CON, 35, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Lata },
  { &hf_ain_triggerCriteriaType, BER_CLASS_CON, 52, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_TriggerCriteriaType },
  { &hf_ain_chargeNumber    , BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ChargeNumber },
  { &hf_ain_callingPartyID  , BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_CallingPartyID },
  { &hf_ain_callingPartyBGID, BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_CallingPartyBGID },
  { &hf_ain_chargePartyStationType, BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ChargePartyStationType },
  { &hf_ain_carrier         , BER_CLASS_CON, 41, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Carrier },
  { &hf_ain_accessCode      , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AccessCode },
  { &hf_ain_collectedAddressInfo, BER_CLASS_CON, 22, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_CollectedAddressInfo },
  { &hf_ain_collectedDigits , BER_CLASS_CON, 23, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_CollectedDigits },
  { &hf_ain_verticalServiceCode, BER_CLASS_CON, 54, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_VerticalServiceCode },
  { &hf_ain_tcm             , BER_CLASS_CON, 51, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Tcm },
  { &hf_ain_originalCalledPartyID, BER_CLASS_CON, 36, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_OriginalCalledPartyID },
  { &hf_ain_redirectingPartyID, BER_CLASS_CON, 43, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_RedirectingPartyID },
  { &hf_ain_redirectionInformation, BER_CLASS_CON, 44, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_RedirectionInformation },
  { &hf_ain_aCGEncountered  , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ACGEncountered },
  { &hf_ain_amp1            , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp1 },
  { &hf_ain_amp2            , BER_CLASS_CON, 109, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp2 },
  { &hf_ain_sap             , BER_CLASS_CON, 81, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Sap },
  { &hf_ain_sTRConnection   , BER_CLASS_CON, 96, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_STRConnection },
  { &hf_ain_aMASequenceNumber, BER_CLASS_CON, 89, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AMASequenceNumber },
  { &hf_ain_extensionParameter, BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_ExtensionParameter },
  { &hf_ain_genericAddressList, BER_CLASS_CON, 107, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_GenericAddressList },
  { &hf_ain_networkSpecificFacilities, BER_CLASS_CON, 108, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_NetworkSpecificFacilities },
  { &hf_ain_cTRConnection   , BER_CLASS_CON, 141, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_CTRConnection },
  { &hf_ain_jurisdictionInformation, BER_CLASS_CON, 147, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_JurisdictionInformation },
  { &hf_ain_prefix          , BER_CLASS_CON, 148, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Prefix },
  { &hf_ain_callingGeodeticLocation, BER_CLASS_CON, 162, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_CallingGeodeticLocation },
  { &hf_ain_triggerInformation, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_TriggerInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_InfoAnalyzedArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   InfoAnalyzedArg_sequence, hf_index, ett_ain_InfoAnalyzedArg);

  return offset;
}


static const ber_sequence_t InfoCollectedArg_sequence[] = {
  { &hf_ain_userID          , BER_CLASS_CON, 53, BER_FLAGS_NOOWNTAG, dissect_ain_UserID },
  { &hf_ain_bearerCapability, BER_CLASS_CON, 13, BER_FLAGS_NOOWNTAG, dissect_ain_BearerCapability },
  { &hf_ain_chargeNumber    , BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ChargeNumber },
  { &hf_ain_lata            , BER_CLASS_CON, 35, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Lata },
  { &hf_ain_carrier         , BER_CLASS_CON, 41, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Carrier },
  { &hf_ain_triggerCriteriaType, BER_CLASS_CON, 52, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_TriggerCriteriaType },
  { &hf_ain_callingPartyID  , BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_CallingPartyID },
  { &hf_ain_chargePartyStationType, BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ChargePartyStationType },
  { &hf_ain_accessCode      , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AccessCode },
  { &hf_ain_collectedAddressInfo, BER_CLASS_CON, 22, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_CollectedAddressInfo },
  { &hf_ain_collectedDigits , BER_CLASS_CON, 23, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_CollectedDigits },
  { &hf_ain_verticalServiceCode, BER_CLASS_CON, 54, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_VerticalServiceCode },
  { &hf_ain_tcm             , BER_CLASS_CON, 51, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Tcm },
  { &hf_ain_originalCalledPartyID, BER_CLASS_CON, 36, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_OriginalCalledPartyID },
  { &hf_ain_redirectingPartyID, BER_CLASS_CON, 43, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_RedirectingPartyID },
  { &hf_ain_redirectionInformation, BER_CLASS_CON, 44, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_RedirectionInformation },
  { &hf_ain_aCGEncountered  , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ACGEncountered },
  { &hf_ain_amp1            , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp1 },
  { &hf_ain_amp2            , BER_CLASS_CON, 109, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp2 },
  { &hf_ain_sap             , BER_CLASS_CON, 81, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Sap },
  { &hf_ain_genericAddressList, BER_CLASS_CON, 107, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_GenericAddressList },
  { &hf_ain_aMASequenceNumber, BER_CLASS_CON, 89, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AMASequenceNumber },
  { &hf_ain_extensionParameter, BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_ExtensionParameter },
  { &hf_ain_prefix          , BER_CLASS_CON, 148, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Prefix },
  { &hf_ain_callingGeodeticLocation, BER_CLASS_CON, 162, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_CallingGeodeticLocation },
  { &hf_ain_triggerInformation, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_TriggerInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_InfoCollectedArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   InfoCollectedArg_sequence, hf_index, ett_ain_InfoCollectedArg);

  return offset;
}


static const ber_sequence_t NetworkBusyArg_sequence[] = {
  { &hf_ain_userID          , BER_CLASS_CON, 53, BER_FLAGS_NOOWNTAG, dissect_ain_UserID },
  { &hf_ain_bearerCapability, BER_CLASS_CON, 13, BER_FLAGS_NOOWNTAG, dissect_ain_BearerCapability },
  { &hf_ain_chargeNumber    , BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ChargeNumber },
  { &hf_ain_lata            , BER_CLASS_CON, 35, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Lata },
  { &hf_ain_triggerCriteriaType, BER_CLASS_CON, 52, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_TriggerCriteriaType },
  { &hf_ain_callingPartyID  , BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_CallingPartyID },
  { &hf_ain_chargePartyStationType, BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ChargePartyStationType },
  { &hf_ain_calledPartyID   , BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_CalledPartyID },
  { &hf_ain_tcm             , BER_CLASS_CON, 51, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Tcm },
  { &hf_ain_originalCalledPartyID, BER_CLASS_CON, 36, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_OriginalCalledPartyID },
  { &hf_ain_carrier         , BER_CLASS_CON, 41, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Carrier },
  { &hf_ain_redirectingPartyID, BER_CLASS_CON, 43, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_RedirectingPartyID },
  { &hf_ain_redirectionInformation, BER_CLASS_CON, 44, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_RedirectionInformation },
  { &hf_ain_aCGEncountered  , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ACGEncountered },
  { &hf_ain_amp1            , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp1 },
  { &hf_ain_amp2            , BER_CLASS_CON, 109, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp2 },
  { &hf_ain_sap             , BER_CLASS_CON, 81, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Sap },
  { &hf_ain_aMASequenceNumber, BER_CLASS_CON, 89, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AMASequenceNumber },
  { &hf_ain_extensionParameter, BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_ExtensionParameter },
  { &hf_ain_notificationIndicator, BER_CLASS_CON, 111, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_NotificationIndicator },
  { &hf_ain_prefix          , BER_CLASS_CON, 148, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Prefix },
  { &hf_ain_triggerInformation, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_TriggerInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_NetworkBusyArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   NetworkBusyArg_sequence, hf_index, ett_ain_NetworkBusyArg);

  return offset;
}


static const ber_sequence_t OAnswerArg_sequence[] = {
  { &hf_ain_userID          , BER_CLASS_CON, 53, BER_FLAGS_NOOWNTAG, dissect_ain_UserID },
  { &hf_ain_bearerCapability, BER_CLASS_CON, 13, BER_FLAGS_NOOWNTAG, dissect_ain_BearerCapability },
  { &hf_ain_notificationIndicator, BER_CLASS_CON, 111, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_NotificationIndicator },
  { &hf_ain_amp1            , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp1 },
  { &hf_ain_amp2            , BER_CLASS_CON, 109, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp2 },
  { &hf_ain_extensionParameter, BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_ExtensionParameter },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_OAnswerArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   OAnswerArg_sequence, hf_index, ett_ain_OAnswerArg);

  return offset;
}


static const ber_sequence_t OAbandonArg_sequence[] = {
  { &hf_ain_userID          , BER_CLASS_CON, 53, BER_FLAGS_NOOWNTAG, dissect_ain_UserID },
  { &hf_ain_bearerCapability, BER_CLASS_CON, 13, BER_FLAGS_NOOWNTAG, dissect_ain_BearerCapability },
  { &hf_ain_ccID            , BER_CLASS_CON, 133, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_CcID },
  { &hf_ain_pointInCall     , BER_CLASS_CON, 135, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_PointInCall },
  { &hf_ain_amp1            , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp1 },
  { &hf_ain_amp2            , BER_CLASS_CON, 109, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp2 },
  { &hf_ain_extensionParameter, BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_ExtensionParameter },
  { &hf_ain_notificationIndicator, BER_CLASS_CON, 111, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_NotificationIndicator },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_OAbandonArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   OAbandonArg_sequence, hf_index, ett_ain_OAbandonArg);

  return offset;
}


static const value_string ain_DisconnectCause_U_vals[] = {
  {   0, "farEnd" },
  { 0, NULL }
};


static int
dissect_ain_DisconnectCause_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_ain_DisconnectCause(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 116, true, dissect_ain_DisconnectCause_U);

  return offset;
}


static const ber_sequence_t ODisconnectArg_sequence[] = {
  { &hf_ain_userID          , BER_CLASS_CON, 53, BER_FLAGS_NOOWNTAG, dissect_ain_UserID },
  { &hf_ain_bearerCapability, BER_CLASS_CON, 13, BER_FLAGS_NOOWNTAG, dissect_ain_BearerCapability },
  { &hf_ain_notificationIndicator, BER_CLASS_CON, 111, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_NotificationIndicator },
  { &hf_ain_amp1            , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp1 },
  { &hf_ain_amp2            , BER_CLASS_CON, 109, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp2 },
  { &hf_ain_extensionParameter, BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_ExtensionParameter },
  { &hf_ain_disconnectCause , BER_CLASS_CON, 116, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_DisconnectCause },
  { &hf_ain_legID           , BER_CLASS_CON, 132, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_LegID },
  { &hf_ain_pointInCall     , BER_CLASS_CON, 135, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_PointInCall },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_ODisconnectArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ODisconnectArg_sequence, hf_index, ett_ain_ODisconnectArg);

  return offset;
}



static int
dissect_ain_OCTET_STRING_SIZE_1_2(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_ain_FeatureActivatorID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 136, true, dissect_ain_OCTET_STRING_SIZE_1_2);

  return offset;
}


static const ber_sequence_t OMidCallArg_sequence[] = {
  { &hf_ain_userID          , BER_CLASS_CON, 53, BER_FLAGS_NOOWNTAG, dissect_ain_UserID },
  { &hf_ain_bearerCapability, BER_CLASS_CON, 13, BER_FLAGS_NOOWNTAG, dissect_ain_BearerCapability },
  { &hf_ain_triggerCriteriaType, BER_CLASS_CON, 52, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_TriggerCriteriaType },
  { &hf_ain_legID           , BER_CLASS_CON, 132, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_LegID },
  { &hf_ain_pointInCall     , BER_CLASS_CON, 135, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_PointInCall },
  { &hf_ain_ccID            , BER_CLASS_CON, 133, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_CcID },
  { &hf_ain_featureActivatorID, BER_CLASS_CON, 136, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_FeatureActivatorID },
  { &hf_ain_chargeNumber    , BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ChargeNumber },
  { &hf_ain_callingPartyID  , BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_CallingPartyID },
  { &hf_ain_callingPartyBGID, BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_CallingPartyBGID },
  { &hf_ain_chargePartyStationType, BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ChargePartyStationType },
  { &hf_ain_carrier         , BER_CLASS_CON, 41, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Carrier },
  { &hf_ain_accessCode      , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AccessCode },
  { &hf_ain_collectedAddressInfo, BER_CLASS_CON, 22, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_CollectedAddressInfo },
  { &hf_ain_collectedDigits , BER_CLASS_CON, 23, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_CollectedDigits },
  { &hf_ain_verticalServiceCode, BER_CLASS_CON, 54, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_VerticalServiceCode },
  { &hf_ain_aCGEncountered  , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ACGEncountered },
  { &hf_ain_notificationIndicator, BER_CLASS_CON, 111, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_NotificationIndicator },
  { &hf_ain_amp1            , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp1 },
  { &hf_ain_amp2            , BER_CLASS_CON, 109, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp2 },
  { &hf_ain_extensionParameter, BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_ExtensionParameter },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_OMidCallArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   OMidCallArg_sequence, hf_index, ett_ain_OMidCallArg);

  return offset;
}


static const ber_sequence_t ONoAnswerArg_sequence[] = {
  { &hf_ain_userID          , BER_CLASS_CON, 53, BER_FLAGS_NOOWNTAG, dissect_ain_UserID },
  { &hf_ain_bearerCapability, BER_CLASS_CON, 13, BER_FLAGS_NOOWNTAG, dissect_ain_BearerCapability },
  { &hf_ain_calledPartyID   , BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_CalledPartyID },
  { &hf_ain_lata            , BER_CLASS_CON, 35, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Lata },
  { &hf_ain_triggerCriteriaType, BER_CLASS_CON, 52, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_TriggerCriteriaType },
  { &hf_ain_chargeNumber    , BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ChargeNumber },
  { &hf_ain_callingPartyID  , BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_CallingPartyID },
  { &hf_ain_chargePartyStationType, BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ChargePartyStationType },
  { &hf_ain_carrier         , BER_CLASS_CON, 41, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Carrier },
  { &hf_ain_originalCalledPartyID, BER_CLASS_CON, 36, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_OriginalCalledPartyID },
  { &hf_ain_redirectingPartyID, BER_CLASS_CON, 43, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_RedirectingPartyID },
  { &hf_ain_redirectionInformation, BER_CLASS_CON, 44, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_RedirectionInformation },
  { &hf_ain_sap             , BER_CLASS_CON, 81, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Sap },
  { &hf_ain_notificationIndicator, BER_CLASS_CON, 111, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_NotificationIndicator },
  { &hf_ain_aCGEncountered  , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ACGEncountered },
  { &hf_ain_amp1            , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp1 },
  { &hf_ain_amp2            , BER_CLASS_CON, 109, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp2 },
  { &hf_ain_sTRConnection   , BER_CLASS_CON, 96, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_STRConnection },
  { &hf_ain_aMASequenceNumber, BER_CLASS_CON, 89, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AMASequenceNumber },
  { &hf_ain_extensionParameter, BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_ExtensionParameter },
  { &hf_ain_cTRConnection   , BER_CLASS_CON, 141, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_CTRConnection },
  { &hf_ain_prefix          , BER_CLASS_CON, 148, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Prefix },
  { &hf_ain_triggerInformation, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_TriggerInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_ONoAnswerArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ONoAnswerArg_sequence, hf_index, ett_ain_ONoAnswerArg);

  return offset;
}


static const ber_sequence_t OSuspendedArg_sequence[] = {
  { &hf_ain_userID          , BER_CLASS_CON, 53, BER_FLAGS_NOOWNTAG, dissect_ain_UserID },
  { &hf_ain_bearerCapability, BER_CLASS_CON, 13, BER_FLAGS_NOOWNTAG, dissect_ain_BearerCapability },
  { &hf_ain_notificationIndicator, BER_CLASS_CON, 111, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_NotificationIndicator },
  { &hf_ain_amp1            , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp1 },
  { &hf_ain_amp2            , BER_CLASS_CON, 109, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp2 },
  { &hf_ain_extensionParameter, BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_ExtensionParameter },
  { &hf_ain_legID           , BER_CLASS_CON, 132, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_LegID },
  { &hf_ain_pointInCall     , BER_CLASS_CON, 135, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_PointInCall },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_OSuspendedArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   OSuspendedArg_sequence, hf_index, ett_ain_OSuspendedArg);

  return offset;
}


static const ber_sequence_t OTermSeizedArg_sequence[] = {
  { &hf_ain_userID          , BER_CLASS_CON, 53, BER_FLAGS_NOOWNTAG, dissect_ain_UserID },
  { &hf_ain_bearerCapability, BER_CLASS_CON, 13, BER_FLAGS_NOOWNTAG, dissect_ain_BearerCapability },
  { &hf_ain_notificationIndicator, BER_CLASS_CON, 111, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_NotificationIndicator },
  { &hf_ain_amp1            , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp1 },
  { &hf_ain_amp2            , BER_CLASS_CON, 109, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp2 },
  { &hf_ain_extensionParameter, BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_ExtensionParameter },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_OTermSeizedArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   OTermSeizedArg_sequence, hf_index, ett_ain_OTermSeizedArg);

  return offset;
}


static const ber_sequence_t OriginationAttemptArg_sequence[] = {
  { &hf_ain_userID          , BER_CLASS_CON, 53, BER_FLAGS_NOOWNTAG, dissect_ain_UserID },
  { &hf_ain_bearerCapability, BER_CLASS_CON, 13, BER_FLAGS_NOOWNTAG, dissect_ain_BearerCapability },
  { &hf_ain_chargeNumber    , BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ChargeNumber },
  { &hf_ain_lata            , BER_CLASS_CON, 35, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Lata },
  { &hf_ain_triggerCriteriaType, BER_CLASS_CON, 52, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_TriggerCriteriaType },
  { &hf_ain_callingPartyID  , BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_CallingPartyID },
  { &hf_ain_chargePartyStationType, BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ChargePartyStationType },
  { &hf_ain_carrier         , BER_CLASS_CON, 41, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Carrier },
  { &hf_ain_aCGEncountered  , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ACGEncountered },
  { &hf_ain_amp1            , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp1 },
  { &hf_ain_amp2            , BER_CLASS_CON, 109, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp2 },
  { &hf_ain_sap             , BER_CLASS_CON, 81, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Sap },
  { &hf_ain_aMASequenceNumber, BER_CLASS_CON, 89, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AMASequenceNumber },
  { &hf_ain_extensionParameter, BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_ExtensionParameter },
  { &hf_ain_notificationIndicator, BER_CLASS_CON, 111, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_NotificationIndicator },
  { &hf_ain_triggerInformation, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_TriggerInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_OriginationAttemptArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   OriginationAttemptArg_sequence, hf_index, ett_ain_OriginationAttemptArg);

  return offset;
}


static const ber_sequence_t RES_resourceClear_sequence[] = {
  { &hf_ain_extensionParameter, BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_ExtensionParameter },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_RES_resourceClear(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RES_resourceClear_sequence, hf_index, ett_ain_RES_resourceClear);

  return offset;
}


static const ber_sequence_t ResourceClearArg_sequence[] = {
  { &hf_ain_clearCause      , BER_CLASS_CON, 21, BER_FLAGS_NOOWNTAG, dissect_ain_ClearCause },
  { &hf_ain_collectedDigits , BER_CLASS_CON, 23, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_CollectedDigits },
  { &hf_ain_collectedAddressInfo, BER_CLASS_CON, 22, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_CollectedAddressInfo },
  { &hf_ain_carrier         , BER_CLASS_CON, 41, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Carrier },
  { &hf_ain_failureCause    , BER_CLASS_CON, 32, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_FailureCause },
  { &hf_ain_amp1            , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp1 },
  { &hf_ain_amp2            , BER_CLASS_CON, 109, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp2 },
  { &hf_ain_aMAMeasurement  , BER_CLASS_CON, 73, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AMAMeasurement },
  { &hf_ain_clearCauseData  , BER_CLASS_CON, 74, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ClearCauseData },
  { &hf_ain_iPReturnBlock   , BER_CLASS_CON, 78, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_IPReturnBlock },
  { &hf_ain_extensionParameter, BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_ExtensionParameter },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_ResourceClearArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ResourceClearArg_sequence, hf_index, ett_ain_ResourceClearArg);

  return offset;
}


static const ber_sequence_t SuccessOutcomeArg_sequence[] = {
  { &hf_ain_userID          , BER_CLASS_CON, 53, BER_FLAGS_NOOWNTAG, dissect_ain_UserID },
  { &hf_ain_bearerCapability, BER_CLASS_CON, 13, BER_FLAGS_NOOWNTAG, dissect_ain_BearerCapability },
  { &hf_ain_notificationIndicator, BER_CLASS_CON, 111, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_NotificationIndicator },
  { &hf_ain_ccID            , BER_CLASS_CON, 133, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_CcID },
  { &hf_ain_legID           , BER_CLASS_CON, 132, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_LegID },
  { &hf_ain_bCMType         , BER_CLASS_CON, 134, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_BCMType },
  { &hf_ain_pointInCall     , BER_CLASS_CON, 135, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_PointInCall },
  { &hf_ain_amp1            , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp1 },
  { &hf_ain_amp2            , BER_CLASS_CON, 109, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp2 },
  { &hf_ain_extensionParameter, BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_ExtensionParameter },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_SuccessOutcomeArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SuccessOutcomeArg_sequence, hf_index, ett_ain_SuccessOutcomeArg);

  return offset;
}


static const ber_sequence_t TAnswerArg_sequence[] = {
  { &hf_ain_userID          , BER_CLASS_CON, 53, BER_FLAGS_NOOWNTAG, dissect_ain_UserID },
  { &hf_ain_bearerCapability, BER_CLASS_CON, 13, BER_FLAGS_NOOWNTAG, dissect_ain_BearerCapability },
  { &hf_ain_notificationIndicator, BER_CLASS_CON, 111, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_NotificationIndicator },
  { &hf_ain_amp1            , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp1 },
  { &hf_ain_amp2            , BER_CLASS_CON, 109, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp2 },
  { &hf_ain_extensionParameter, BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_ExtensionParameter },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_TAnswerArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TAnswerArg_sequence, hf_index, ett_ain_TAnswerArg);

  return offset;
}



static int
dissect_ain_OCTET_STRING_SIZE_2_3(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_ain_BusyCause(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 14, true, dissect_ain_OCTET_STRING_SIZE_2_3);

  return offset;
}


static const value_string ain_BusyType_U_vals[] = {
  {   0, "callCanBeOffered" },
  {   1, "callCannotBeOffered" },
  { 0, NULL }
};


static int
dissect_ain_BusyType_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_ain_BusyType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 94, true, dissect_ain_BusyType_U);

  return offset;
}



static int
dissect_ain_CalledPartyStationType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 16, true, dissect_ain_INTEGER_0_99);

  return offset;
}



static int
dissect_ain_OCTET_STRING(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_ain_GenericName(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 33, true, dissect_ain_OCTET_STRING);

  return offset;
}


static const ber_sequence_t TBusyArg_sequence[] = {
  { &hf_ain_userID          , BER_CLASS_CON, 53, BER_FLAGS_NOOWNTAG, dissect_ain_UserID },
  { &hf_ain_bearerCapability, BER_CLASS_CON, 13, BER_FLAGS_NOOWNTAG, dissect_ain_BearerCapability },
  { &hf_ain_calledPartyID   , BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_CalledPartyID },
  { &hf_ain_lata            , BER_CLASS_CON, 35, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Lata },
  { &hf_ain_triggerCriteriaType, BER_CLASS_CON, 52, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_TriggerCriteriaType },
  { &hf_ain_chargeNumber    , BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ChargeNumber },
  { &hf_ain_callingPartyID  , BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_CallingPartyID },
  { &hf_ain_chargePartyStationType, BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ChargePartyStationType },
  { &hf_ain_originalCalledPartyID, BER_CLASS_CON, 36, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_OriginalCalledPartyID },
  { &hf_ain_redirectingPartyID, BER_CLASS_CON, 43, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_RedirectingPartyID },
  { &hf_ain_redirectionInformation, BER_CLASS_CON, 44, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_RedirectionInformation },
  { &hf_ain_busyCause       , BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_BusyCause },
  { &hf_ain_busyType        , BER_CLASS_CON, 94, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_BusyType },
  { &hf_ain_calledPartyStationType, BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_CalledPartyStationType },
  { &hf_ain_sap             , BER_CLASS_CON, 81, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Sap },
  { &hf_ain_genericName     , BER_CLASS_CON, 33, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_GenericName },
  { &hf_ain_notificationIndicator, BER_CLASS_CON, 111, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_NotificationIndicator },
  { &hf_ain_aCGEncountered  , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ACGEncountered },
  { &hf_ain_amp1            , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp1 },
  { &hf_ain_amp2            , BER_CLASS_CON, 109, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp2 },
  { &hf_ain_sTRConnection   , BER_CLASS_CON, 96, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_STRConnection },
  { &hf_ain_aMASequenceNumber, BER_CLASS_CON, 89, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AMASequenceNumber },
  { &hf_ain_extensionParameter, BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_ExtensionParameter },
  { &hf_ain_cTRConnection   , BER_CLASS_CON, 141, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_CTRConnection },
  { &hf_ain_triggerInformation, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_TriggerInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_TBusyArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TBusyArg_sequence, hf_index, ett_ain_TBusyArg);

  return offset;
}


static const ber_sequence_t TDisconnectArg_sequence[] = {
  { &hf_ain_userID          , BER_CLASS_CON, 53, BER_FLAGS_NOOWNTAG, dissect_ain_UserID },
  { &hf_ain_bearerCapability, BER_CLASS_CON, 13, BER_FLAGS_NOOWNTAG, dissect_ain_BearerCapability },
  { &hf_ain_ccID            , BER_CLASS_CON, 133, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_CcID },
  { &hf_ain_legID           , BER_CLASS_CON, 132, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_LegID },
  { &hf_ain_pointInCall     , BER_CLASS_CON, 135, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_PointInCall },
  { &hf_ain_disconnectCause , BER_CLASS_CON, 116, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_DisconnectCause },
  { &hf_ain_amp1            , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp1 },
  { &hf_ain_amp2            , BER_CLASS_CON, 109, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp2 },
  { &hf_ain_extensionParameter, BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_ExtensionParameter },
  { &hf_ain_notificationIndicator, BER_CLASS_CON, 111, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_NotificationIndicator },
  { &hf_ain_aMASequenceNumber, BER_CLASS_CON, 89, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AMASequenceNumber },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_TDisconnectArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TDisconnectArg_sequence, hf_index, ett_ain_TDisconnectArg);

  return offset;
}



static int
dissect_ain_DTMFDigitsDetected(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 153, true, dissect_ain_AINDigits);

  return offset;
}


static const ber_sequence_t TDTMFEnteredArg_sequence[] = {
  { &hf_ain_userID          , BER_CLASS_CON, 53, BER_FLAGS_NOOWNTAG, dissect_ain_UserID },
  { &hf_ain_bearerCapability, BER_CLASS_CON, 13, BER_FLAGS_NOOWNTAG, dissect_ain_BearerCapability },
  { &hf_ain_dTMFDigitsDetected, BER_CLASS_CON, 153, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_DTMFDigitsDetected },
  { &hf_ain_amp1            , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp1 },
  { &hf_ain_amp2            , BER_CLASS_CON, 109, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp2 },
  { &hf_ain_extensionParameter, BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_ExtensionParameter },
  { &hf_ain_notificationIndicator, BER_CLASS_CON, 111, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_NotificationIndicator },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_TDTMFEnteredArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TDTMFEnteredArg_sequence, hf_index, ett_ain_TDTMFEnteredArg);

  return offset;
}


static const ber_sequence_t TMidCallArg_sequence[] = {
  { &hf_ain_userID          , BER_CLASS_CON, 53, BER_FLAGS_NOOWNTAG, dissect_ain_UserID },
  { &hf_ain_bearerCapability, BER_CLASS_CON, 13, BER_FLAGS_NOOWNTAG, dissect_ain_BearerCapability },
  { &hf_ain_calledPartyID   , BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_CalledPartyID },
  { &hf_ain_triggerCriteriaType, BER_CLASS_CON, 52, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_TriggerCriteriaType },
  { &hf_ain_legID           , BER_CLASS_CON, 132, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_LegID },
  { &hf_ain_pointInCall     , BER_CLASS_CON, 135, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_PointInCall },
  { &hf_ain_ccID            , BER_CLASS_CON, 133, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_CcID },
  { &hf_ain_featureActivatorID, BER_CLASS_CON, 136, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_FeatureActivatorID },
  { &hf_ain_chargeNumber    , BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ChargeNumber },
  { &hf_ain_callingPartyID  , BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_CallingPartyID },
  { &hf_ain_callingPartyBGID, BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_CallingPartyBGID },
  { &hf_ain_chargePartyStationType, BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ChargePartyStationType },
  { &hf_ain_carrier         , BER_CLASS_CON, 41, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Carrier },
  { &hf_ain_accessCode      , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AccessCode },
  { &hf_ain_collectedAddressInfo, BER_CLASS_CON, 22, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_CollectedAddressInfo },
  { &hf_ain_collectedDigits , BER_CLASS_CON, 23, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_CollectedDigits },
  { &hf_ain_verticalServiceCode, BER_CLASS_CON, 54, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_VerticalServiceCode },
  { &hf_ain_aCGEncountered  , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ACGEncountered },
  { &hf_ain_notificationIndicator, BER_CLASS_CON, 111, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_NotificationIndicator },
  { &hf_ain_amp1            , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp1 },
  { &hf_ain_amp2            , BER_CLASS_CON, 109, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp2 },
  { &hf_ain_extensionParameter, BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_ExtensionParameter },
  { &hf_ain_aMASequenceNumber, BER_CLASS_CON, 89, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AMASequenceNumber },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_TMidCallArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TMidCallArg_sequence, hf_index, ett_ain_TMidCallArg);

  return offset;
}


static const ber_sequence_t TNoAnswerArg_sequence[] = {
  { &hf_ain_userID          , BER_CLASS_CON, 53, BER_FLAGS_NOOWNTAG, dissect_ain_UserID },
  { &hf_ain_bearerCapability, BER_CLASS_CON, 13, BER_FLAGS_NOOWNTAG, dissect_ain_BearerCapability },
  { &hf_ain_calledPartyID   , BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_CalledPartyID },
  { &hf_ain_lata            , BER_CLASS_CON, 35, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Lata },
  { &hf_ain_triggerCriteriaType, BER_CLASS_CON, 52, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_TriggerCriteriaType },
  { &hf_ain_chargeNumber    , BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ChargeNumber },
  { &hf_ain_callingPartyID  , BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_CallingPartyID },
  { &hf_ain_chargePartyStationType, BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ChargePartyStationType },
  { &hf_ain_originalCalledPartyID, BER_CLASS_CON, 36, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_OriginalCalledPartyID },
  { &hf_ain_redirectingPartyID, BER_CLASS_CON, 43, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_RedirectingPartyID },
  { &hf_ain_redirectionInformation, BER_CLASS_CON, 44, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_RedirectionInformation },
  { &hf_ain_calledPartyStationType, BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_CalledPartyStationType },
  { &hf_ain_sap             , BER_CLASS_CON, 81, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Sap },
  { &hf_ain_genericName     , BER_CLASS_CON, 33, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_GenericName },
  { &hf_ain_notificationIndicator, BER_CLASS_CON, 111, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_NotificationIndicator },
  { &hf_ain_aCGEncountered  , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ACGEncountered },
  { &hf_ain_amp1            , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp1 },
  { &hf_ain_amp2            , BER_CLASS_CON, 109, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp2 },
  { &hf_ain_sTRConnection   , BER_CLASS_CON, 96, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_STRConnection },
  { &hf_ain_aMASequenceNumber, BER_CLASS_CON, 89, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AMASequenceNumber },
  { &hf_ain_extensionParameter, BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_ExtensionParameter },
  { &hf_ain_cTRConnection   , BER_CLASS_CON, 141, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_CTRConnection },
  { &hf_ain_triggerInformation, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_TriggerInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_TNoAnswerArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TNoAnswerArg_sequence, hf_index, ett_ain_TNoAnswerArg);

  return offset;
}



static int
dissect_ain_RTPServiceIndicator(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 144, true, dissect_ain_OCTET_STRING_SIZE_1);

  return offset;
}


static const ber_sequence_t TerminationAttemptArg_sequence[] = {
  { &hf_ain_userID          , BER_CLASS_CON, 53, BER_FLAGS_NOOWNTAG, dissect_ain_UserID },
  { &hf_ain_bearerCapability, BER_CLASS_CON, 13, BER_FLAGS_NOOWNTAG, dissect_ain_BearerCapability },
  { &hf_ain_calledPartyID   , BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_CalledPartyID },
  { &hf_ain_lata            , BER_CLASS_CON, 35, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Lata },
  { &hf_ain_triggerCriteriaType, BER_CLASS_CON, 52, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_TriggerCriteriaType },
  { &hf_ain_calledPartyStationType, BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_CalledPartyStationType },
  { &hf_ain_chargeNumber    , BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ChargeNumber },
  { &hf_ain_callingPartyID  , BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_CallingPartyID },
  { &hf_ain_chargePartyStationType, BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ChargePartyStationType },
  { &hf_ain_tcm             , BER_CLASS_CON, 51, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Tcm },
  { &hf_ain_originalCalledPartyID, BER_CLASS_CON, 36, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_OriginalCalledPartyID },
  { &hf_ain_redirectingPartyID, BER_CLASS_CON, 43, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_RedirectingPartyID },
  { &hf_ain_redirectionInformation, BER_CLASS_CON, 44, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_RedirectionInformation },
  { &hf_ain_genericName     , BER_CLASS_CON, 33, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_GenericName },
  { &hf_ain_aCGEncountered  , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ACGEncountered },
  { &hf_ain_amp1            , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp1 },
  { &hf_ain_amp2            , BER_CLASS_CON, 109, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp2 },
  { &hf_ain_sap             , BER_CLASS_CON, 81, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Sap },
  { &hf_ain_sTRConnection   , BER_CLASS_CON, 96, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_STRConnection },
  { &hf_ain_aMASequenceNumber, BER_CLASS_CON, 89, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AMASequenceNumber },
  { &hf_ain_extensionParameter, BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_ExtensionParameter },
  { &hf_ain_cTRConnection   , BER_CLASS_CON, 141, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_CTRConnection },
  { &hf_ain_rTPServiceIndicator, BER_CLASS_CON, 144, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_RTPServiceIndicator },
  { &hf_ain_genericAddressList, BER_CLASS_CON, 107, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_GenericAddressList },
  { &hf_ain_triggerInformation, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_TriggerInformation },
  { &hf_ain_callingGeodeticLocation, BER_CLASS_CON, 162, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_CallingGeodeticLocation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_TerminationAttemptArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TerminationAttemptArg_sequence, hf_index, ett_ain_TerminationAttemptArg);

  return offset;
}


static const ber_sequence_t TermResourceAvailableArg_sequence[] = {
  { &hf_ain_userID          , BER_CLASS_CON, 53, BER_FLAGS_NOOWNTAG, dissect_ain_UserID },
  { &hf_ain_bearerCapability, BER_CLASS_CON, 13, BER_FLAGS_NOOWNTAG, dissect_ain_BearerCapability },
  { &hf_ain_notificationIndicator, BER_CLASS_CON, 111, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_NotificationIndicator },
  { &hf_ain_amp1            , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp1 },
  { &hf_ain_amp2            , BER_CLASS_CON, 109, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp2 },
  { &hf_ain_extensionParameter, BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_ExtensionParameter },
  { &hf_ain_calledPartyID   , BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_CalledPartyID },
  { &hf_ain_lata            , BER_CLASS_CON, 35, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Lata },
  { &hf_ain_triggerCriteriaType, BER_CLASS_CON, 52, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_TriggerCriteriaType },
  { &hf_ain_chargeNumber    , BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ChargeNumber },
  { &hf_ain_callingPartyID  , BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_CallingPartyID },
  { &hf_ain_chargePartyStationType, BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ChargePartyStationType },
  { &hf_ain_originalCalledPartyID, BER_CLASS_CON, 36, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_OriginalCalledPartyID },
  { &hf_ain_redirectingPartyID, BER_CLASS_CON, 43, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_RedirectingPartyID },
  { &hf_ain_redirectionInformation, BER_CLASS_CON, 44, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_RedirectionInformation },
  { &hf_ain_calledPartyStationType, BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_CalledPartyStationType },
  { &hf_ain_sap             , BER_CLASS_CON, 81, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Sap },
  { &hf_ain_genericName     , BER_CLASS_CON, 33, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_GenericName },
  { &hf_ain_aCGEncountered  , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ACGEncountered },
  { &hf_ain_sTRConnection   , BER_CLASS_CON, 96, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_STRConnection },
  { &hf_ain_aMASequenceNumber, BER_CLASS_CON, 89, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AMASequenceNumber },
  { &hf_ain_cTRConnection   , BER_CLASS_CON, 141, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_CTRConnection },
  { &hf_ain_triggerInformation, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_TriggerInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_TermResourceAvailableArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TermResourceAvailableArg_sequence, hf_index, ett_ain_TermResourceAvailableArg);

  return offset;
}


static const ber_sequence_t TimeoutArg_sequence[] = {
  { &hf_ain_userID          , BER_CLASS_CON, 53, BER_FLAGS_NOOWNTAG, dissect_ain_UserID },
  { &hf_ain_bearerCapability, BER_CLASS_CON, 13, BER_FLAGS_NOOWNTAG, dissect_ain_BearerCapability },
  { &hf_ain_legID           , BER_CLASS_CON, 132, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_LegID },
  { &hf_ain_bCMType         , BER_CLASS_CON, 134, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_BCMType },
  { &hf_ain_pointInCall     , BER_CLASS_CON, 135, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_PointInCall },
  { &hf_ain_ccID            , BER_CLASS_CON, 133, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_CcID },
  { &hf_ain_aCGEncountered  , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ACGEncountered },
  { &hf_ain_amp1            , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp1 },
  { &hf_ain_amp2            , BER_CLASS_CON, 109, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp2 },
  { &hf_ain_extensionParameter, BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_ExtensionParameter },
  { &hf_ain_notificationIndicator, BER_CLASS_CON, 111, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_NotificationIndicator },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_TimeoutArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TimeoutArg_sequence, hf_index, ett_ain_TimeoutArg);

  return offset;
}



static int
dissect_ain_OutpulseNumber(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 37, true, dissect_ain_AINDigits);

  return offset;
}



static int
dissect_ain_OCTET_STRING_SIZE_5(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_ain_PrimaryTrunkGroup(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 42, true, dissect_ain_OCTET_STRING_SIZE_5);

  return offset;
}



static int
dissect_ain_AlternateTrunkGroup(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 5, true, dissect_ain_OCTET_STRING_SIZE_5);

  return offset;
}



static int
dissect_ain_SecondAlternateTrunkGroup(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 48, true, dissect_ain_OCTET_STRING_SIZE_5);

  return offset;
}



static int
dissect_ain_AlternateCarrier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 4, true, dissect_ain_CarrierFormat);

  return offset;
}



static int
dissect_ain_SecondAlternateCarrier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 47, true, dissect_ain_CarrierFormat);

  return offset;
}


static const value_string ain_PassiveLegTreatment_U_vals[] = {
  {   0, "dialToneOn" },
  {   1, "ringBackAudibleRingingToneOn" },
  {   3, "networkCongestionReorderToneOn" },
  {   4, "busyToneOn" },
  {   5, "confirmationTone" },
  {   7, "callWaitingTone" },
  {  63, "tonesOff" },
  {  64, "alertingOnPattern0Normal" },
  {  65, "alertingOnPattern1DistinctiveIntergroup" },
  {  66, "alertingOnPattern2DistinctiveSpecial" },
  {  67, "alertingOnPattern3EKTS" },
  {  68, "alertingOnPattern4ReminderRing" },
  {  79, "alertingOff" },
  {  17, "recallDialToneOn" },
  {  18, "bargeInToneOn" },
  { 251, "incomingAdditionalCallTone" },
  { 252, "priorityAdditionalCallTone" },
  { 253, "expensiveRouteWarningTone" },
  {  19, "campOnTone" },
  {  20, "receiverOffHookTone" },
  {  21, "callingCardServiceTone" },
  {  22, "stutterDialTone" },
  {  23, "silence" },
  { 0, NULL }
};


static int
dissect_ain_PassiveLegTreatment_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_ain_PassiveLegTreatment(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 39, true, dissect_ain_PassiveLegTreatment_U);

  return offset;
}



static int
dissect_ain_BillingIndicator(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_ain_PrimaryBillingIndicator(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 40, true, dissect_ain_BillingIndicator);

  return offset;
}



static int
dissect_ain_AlternateBillingIndicator(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 3, true, dissect_ain_BillingIndicator);

  return offset;
}



static int
dissect_ain_SecondAlternateBillingIndicator(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 46, true, dissect_ain_BillingIndicator);

  return offset;
}



static int
dissect_ain_OverflowBillingIndicator(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 38, true, dissect_ain_BillingIndicator);

  return offset;
}



static int
dissect_ain_AMAAlternateBillingNumber(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 6, true, dissect_ain_AINDigits);

  return offset;
}



static int
dissect_ain_AMABusinessCustomerID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 7, true, dissect_ain_AINDigits);

  return offset;
}



static int
dissect_ain_AMALineNumber(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 9, true, dissect_ain_AINDigits);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_2_OF_AMALineNumber_sequence_of[1] = {
  { &hf_ain_aMALineNumberList_item, BER_CLASS_CON, 9, BER_FLAGS_NOOWNTAG, dissect_ain_AMALineNumber },
};

static int
dissect_ain_SEQUENCE_SIZE_1_2_OF_AMALineNumber(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_SIZE_1_2_OF_AMALineNumber_sequence_of, hf_index, ett_ain_SEQUENCE_SIZE_1_2_OF_AMALineNumber);

  return offset;
}



static int
dissect_ain_AMAslpID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *parameter_tvb;
  proto_tree *subtree;

    offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &parameter_tvb);


  if (!parameter_tvb)
    return offset;

  subtree = proto_item_add_subtree(actx->created_item, ett_ain_amaslpid);

  proto_tree_add_item(subtree, hf_ain_amaslpid, parameter_tvb, 0, tvb_reported_length_remaining(parameter_tvb, 0), ENC_BCD_DIGITS_0_9|ENC_LITTLE_ENDIAN);


  return offset;
}



static int
dissect_ain_AMADigitsDialedWC(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 8, true, dissect_ain_AINDigits);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_5_OF_AMADigitsDialedWC_sequence_of[1] = {
  { &hf_ain_aMADigitsDialedWCList_item, BER_CLASS_CON, 8, BER_FLAGS_NOOWNTAG, dissect_ain_AMADigitsDialedWC },
};

static int
dissect_ain_SEQUENCE_SIZE_1_5_OF_AMADigitsDialedWC(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_SIZE_1_5_OF_AMADigitsDialedWC_sequence_of, hf_index, ett_ain_SEQUENCE_SIZE_1_5_OF_AMADigitsDialedWC);

  return offset;
}



static int
dissect_ain_MsrID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 106, true, dissect_ain_AINDigits);

  return offset;
}


static const value_string ain_ServiceProviderID_vals[] = {
  {  87, "ocn" },
  { 106, "msrID" },
  { 0, NULL }
};

static const ber_choice_t ServiceProviderID_choice[] = {
  {  87, &hf_ain_ocn             , BER_CLASS_CON, 87, BER_FLAGS_NOOWNTAG, dissect_ain_Ocn },
  { 106, &hf_ain_msrID           , BER_CLASS_CON, 106, BER_FLAGS_NOOWNTAG, dissect_ain_MsrID },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_ServiceProviderID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ServiceProviderID_choice, hf_index, ett_ain_ServiceProviderID,
                                 NULL);

  return offset;
}



static int
dissect_ain_INTEGER_0_32767(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_ain_ServiceContext(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 83, true, dissect_ain_INTEGER_0_32767);

  return offset;
}



static int
dissect_ain_AMABillingFeature(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 88, true, dissect_ain_AINDigits);

  return offset;
}


static const value_string ain_CarrierUsage_U_vals[] = {
  {   0, "alwaysOverride" },
  {   1, "onlyInterLATAOverride" },
  { 0, NULL }
};


static int
dissect_ain_CarrierUsage_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_ain_CarrierUsage(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 79, true, dissect_ain_CarrierUsage_U);

  return offset;
}



static int
dissect_ain_ForwardCallIndicator(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 113, true, dissect_ain_OCTET_STRING_SIZE_2);

  return offset;
}



static int
dissect_ain_OCTET_STRING_SIZE_7(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_ain_AMAServiceProviderID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 101, true, dissect_ain_OCTET_STRING_SIZE_7);

  return offset;
}



static int
dissect_ain_OCTET_STRING_SIZE_2_11(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_ain_GenericDigits(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 149, true, dissect_ain_OCTET_STRING_SIZE_2_11);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_5_OF_GenericDigits_sequence_of[1] = {
  { &hf_ain__untag_item_02  , BER_CLASS_CON, 149, BER_FLAGS_NOOWNTAG, dissect_ain_GenericDigits },
};

static int
dissect_ain_SEQUENCE_SIZE_1_5_OF_GenericDigits(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_SIZE_1_5_OF_GenericDigits_sequence_of, hf_index, ett_ain_SEQUENCE_SIZE_1_5_OF_GenericDigits);

  return offset;
}



static int
dissect_ain_GenericDigitsList(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 150, true, dissect_ain_SEQUENCE_SIZE_1_5_OF_GenericDigits);

  return offset;
}


static int * const ApplyRestrictions_U_bits[] = {
  &hf_ain_ApplyRestrictions_U_code,
  &hf_ain_ApplyRestrictions_U_toll,
  NULL
};

static int
dissect_ain_ApplyRestrictions_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    ApplyRestrictions_U_bits, 2, hf_index, ett_ain_ApplyRestrictions_U,
                                    NULL);

  return offset;
}



static int
dissect_ain_ApplyRestrictions(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 152, true, dissect_ain_ApplyRestrictions_U);

  return offset;
}


static const value_string ain_DisplayInformation_vals[] = {
  {   0, "blank" },
  {   1, "skip" },
  {   2, "continuation" },
  {   3, "calledAddress" },
  {   4, "cause" },
  {   5, "progressIndicator" },
  {   6, "notificationIndicator" },
  {   7, "prompt" },
  {   8, "accumulatedDigits" },
  {   9, "status" },
  {  10, "inband" },
  {  11, "callingAddress" },
  {  12, "reason" },
  {  13, "callingPartyName" },
  {  14, "calledPartyName" },
  {  15, "originalCalledName" },
  {  16, "redirectingName" },
  {  17, "connectedName" },
  {  18, "origRestrictions" },
  {  19, "dateTimeOfDay" },
  {  20, "callAppearanceID" },
  {  21, "featureAddress" },
  {  22, "redirectionName" },
  {  23, "redirectionNumber" },
  {  24, "redirectingNumber" },
  {  25, "originalCalledNumber" },
  {  26, "connectedNumber" },
  {  30, "text" },
  {  31, "redirectingReason" },
  { 0, NULL }
};

static const ber_choice_t DisplayInformation_choice[] = {
  {   0, &hf_ain_blank           , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ain_OCTET_STRING_SIZE_1_20 },
  {   1, &hf_ain_skip            , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ain_OCTET_STRING_SIZE_1_20 },
  {   2, &hf_ain_continuation    , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_ain_OCTET_STRING_SIZE_1_20 },
  {   3, &hf_ain_calledAddress   , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_ain_OCTET_STRING_SIZE_1_20 },
  {   4, &hf_ain_cause           , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_ain_OCTET_STRING_SIZE_1_20 },
  {   5, &hf_ain_progressIndicator, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_ain_OCTET_STRING_SIZE_1_20 },
  {   6, &hf_ain_displayInformation_notificationIndicator, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_ain_OCTET_STRING_SIZE_1_20 },
  {   7, &hf_ain_prompt          , BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_ain_OCTET_STRING_SIZE_1_20 },
  {   8, &hf_ain_accumulatedDigits, BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_ain_OCTET_STRING_SIZE_1_20 },
  {   9, &hf_ain_status          , BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_ain_OCTET_STRING_SIZE_1_20 },
  {  10, &hf_ain_inband          , BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_ain_OCTET_STRING_SIZE_1_20 },
  {  11, &hf_ain_callingAddress  , BER_CLASS_CON, 11, BER_FLAGS_IMPLTAG, dissect_ain_OCTET_STRING_SIZE_1_20 },
  {  12, &hf_ain_reason          , BER_CLASS_CON, 12, BER_FLAGS_IMPLTAG, dissect_ain_OCTET_STRING_SIZE_1_20 },
  {  13, &hf_ain_callingPartyName, BER_CLASS_CON, 13, BER_FLAGS_IMPLTAG, dissect_ain_OCTET_STRING_SIZE_1_20 },
  {  14, &hf_ain_calledPartyName , BER_CLASS_CON, 14, BER_FLAGS_IMPLTAG, dissect_ain_OCTET_STRING_SIZE_1_20 },
  {  15, &hf_ain_originalCalledName, BER_CLASS_CON, 15, BER_FLAGS_IMPLTAG, dissect_ain_OCTET_STRING_SIZE_1_20 },
  {  16, &hf_ain_redirectingName , BER_CLASS_CON, 16, BER_FLAGS_IMPLTAG, dissect_ain_OCTET_STRING_SIZE_1_20 },
  {  17, &hf_ain_connectedName   , BER_CLASS_CON, 17, BER_FLAGS_IMPLTAG, dissect_ain_OCTET_STRING_SIZE_1_20 },
  {  18, &hf_ain_origRestrictions, BER_CLASS_CON, 18, BER_FLAGS_IMPLTAG, dissect_ain_OCTET_STRING_SIZE_1_20 },
  {  19, &hf_ain_dateTimeOfDay   , BER_CLASS_CON, 19, BER_FLAGS_IMPLTAG, dissect_ain_OCTET_STRING_SIZE_1_20 },
  {  20, &hf_ain_callAppearanceID, BER_CLASS_CON, 20, BER_FLAGS_IMPLTAG, dissect_ain_OCTET_STRING_SIZE_1_20 },
  {  21, &hf_ain_featureAddress  , BER_CLASS_CON, 21, BER_FLAGS_IMPLTAG, dissect_ain_OCTET_STRING_SIZE_1_20 },
  {  22, &hf_ain_redirectionName , BER_CLASS_CON, 22, BER_FLAGS_IMPLTAG, dissect_ain_OCTET_STRING_SIZE_1_20 },
  {  23, &hf_ain_redirectionNumber, BER_CLASS_CON, 23, BER_FLAGS_IMPLTAG, dissect_ain_OCTET_STRING_SIZE_1_20 },
  {  24, &hf_ain_redirectingNumber, BER_CLASS_CON, 24, BER_FLAGS_IMPLTAG, dissect_ain_OCTET_STRING_SIZE_1_20 },
  {  25, &hf_ain_originalCalledNumber, BER_CLASS_CON, 25, BER_FLAGS_IMPLTAG, dissect_ain_OCTET_STRING_SIZE_1_20 },
  {  26, &hf_ain_connectedNumber , BER_CLASS_CON, 26, BER_FLAGS_IMPLTAG, dissect_ain_OCTET_STRING_SIZE_1_20 },
  {  30, &hf_ain_text            , BER_CLASS_CON, 30, BER_FLAGS_IMPLTAG, dissect_ain_OCTET_STRING_SIZE_1_20 },
  {  31, &hf_ain_redirectingReason, BER_CLASS_CON, 31, BER_FLAGS_IMPLTAG, dissect_ain_OCTET_STRING_SIZE_1_20 },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_DisplayInformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 DisplayInformation_choice, hf_index, ett_ain_DisplayInformation,
                                 NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_15_OF_DisplayInformation_sequence_of[1] = {
  { &hf_ain__untag_item     , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ain_DisplayInformation },
};

static int
dissect_ain_SEQUENCE_SIZE_1_15_OF_DisplayInformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_SIZE_1_15_OF_DisplayInformation_sequence_of, hf_index, ett_ain_SEQUENCE_SIZE_1_15_OF_DisplayInformation);

  return offset;
}



static int
dissect_ain_DisplayText(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 26, true, dissect_ain_SEQUENCE_SIZE_1_15_OF_DisplayInformation);

  return offset;
}


static const ber_sequence_t AnalyzeRouteArg_sequence[] = {
  { &hf_ain_chargeNumber    , BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ChargeNumber },
  { &hf_ain_callingPartyID  , BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_CallingPartyID },
  { &hf_ain_chargePartyStationType, BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ChargePartyStationType },
  { &hf_ain_calledPartyID   , BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_CalledPartyID },
  { &hf_ain_outpulseNumber  , BER_CLASS_CON, 37, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_OutpulseNumber },
  { &hf_ain_tcm             , BER_CLASS_CON, 51, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Tcm },
  { &hf_ain_primaryTrunkGroup, BER_CLASS_CON, 42, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_PrimaryTrunkGroup },
  { &hf_ain_alternateTrunkGroup, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AlternateTrunkGroup },
  { &hf_ain_secondAlternateTrunkGroup, BER_CLASS_CON, 48, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_SecondAlternateTrunkGroup },
  { &hf_ain_carrier         , BER_CLASS_CON, 41, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Carrier },
  { &hf_ain_alternateCarrier, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AlternateCarrier },
  { &hf_ain_secondAlternateCarrier, BER_CLASS_CON, 47, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_SecondAlternateCarrier },
  { &hf_ain_passiveLegTreatment, BER_CLASS_CON, 39, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_PassiveLegTreatment },
  { &hf_ain_redirectingPartyID, BER_CLASS_CON, 43, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_RedirectingPartyID },
  { &hf_ain_primaryBillingIndicator, BER_CLASS_CON, 40, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_PrimaryBillingIndicator },
  { &hf_ain_alternateBillingIndicator, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AlternateBillingIndicator },
  { &hf_ain_secondAlternateBillingIndicator, BER_CLASS_CON, 46, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_SecondAlternateBillingIndicator },
  { &hf_ain_overflowBillingIndicator, BER_CLASS_CON, 38, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_OverflowBillingIndicator },
  { &hf_ain_aMAAlternateBillingNumber, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AMAAlternateBillingNumber },
  { &hf_ain_aMABusinessCustomerID, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AMABusinessCustomerID },
  { &hf_ain_aMALineNumberList, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_SEQUENCE_SIZE_1_2_OF_AMALineNumber },
  { &hf_ain_aMAslpID        , BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_ain_AMAslpID },
  { &hf_ain_aMADigitsDialedWCList, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_SEQUENCE_SIZE_1_5_OF_AMADigitsDialedWC },
  { &hf_ain_amp1            , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp1 },
  { &hf_ain_amp2            , BER_CLASS_CON, 109, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp2 },
  { &hf_ain_serviceProviderID, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ain_ServiceProviderID },
  { &hf_ain_serviceContext  , BER_CLASS_CON, 83, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ServiceContext },
  { &hf_ain_aMABillingFeature, BER_CLASS_CON, 88, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AMABillingFeature },
  { &hf_ain_aMASequenceNumber, BER_CLASS_CON, 89, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AMASequenceNumber },
  { &hf_ain_redirectionInformation, BER_CLASS_CON, 44, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_RedirectionInformation },
  { &hf_ain_carrierUsage    , BER_CLASS_CON, 79, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_CarrierUsage },
  { &hf_ain_extensionParameter, BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_ExtensionParameter },
  { &hf_ain_genericAddressList, BER_CLASS_CON, 107, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_GenericAddressList },
  { &hf_ain_networkSpecificFacilities, BER_CLASS_CON, 108, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_NetworkSpecificFacilities },
  { &hf_ain_callingPartyBGID, BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_CallingPartyBGID },
  { &hf_ain_forwardCallIndicator, BER_CLASS_CON, 113, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ForwardCallIndicator },
  { &hf_ain_aMAServiceProviderID, BER_CLASS_CON, 101, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AMAServiceProviderID },
  { &hf_ain_prefix          , BER_CLASS_CON, 148, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Prefix },
  { &hf_ain_genericDigitsList, BER_CLASS_CON, 150, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_GenericDigitsList },
  { &hf_ain_applyRestrictions, BER_CLASS_CON, 152, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ApplyRestrictions },
  { &hf_ain_displayText     , BER_CLASS_CON, 26, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_DisplayText },
  { &hf_ain_genericName     , BER_CLASS_CON, 33, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_GenericName },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_AnalyzeRouteArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AnalyzeRouteArg_sequence, hf_index, ett_ain_AnalyzeRouteArg);

  return offset;
}


static const value_string ain_ControllingLegTreatment_U_vals[] = {
  {   0, "dialToneOn" },
  {   1, "ringBackAudibleRingingToneOn" },
  {   3, "networkCongestionReorderToneOn" },
  {   4, "busyToneOn" },
  {   5, "confirmationTone" },
  {   7, "callWaitingTone" },
  {  63, "tonesOff" },
  {  64, "alertingOnPattern0Normal" },
  {  65, "alertingOnPattern1DistinctiveIntergroup" },
  {  66, "alertingOnPattern2DistinctiveSpecial" },
  {  67, "alertingOnPattern3EKTS" },
  {  68, "alertingOnPattern4ReminderRing" },
  {  79, "alertingOff" },
  {  17, "recallDialToneOn" },
  {  18, "bargeInToneOn" },
  { 251, "incomingAdditionalCallTone" },
  { 252, "priorityAdditionalCallTone" },
  { 253, "expensiveRouteWarningTone" },
  {  19, "campOnTone" },
  {  20, "receiverOffHookTone" },
  {  21, "callingCardServiceTone" },
  {  22, "stutterDialTone" },
  {  23, "silence" },
  {  24, "onHookTR30WithIndication" },
  {  25, "onHookTR30NoIndication" },
  { 0, NULL }
};


static int
dissect_ain_ControllingLegTreatment_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_ain_ControllingLegTreatment(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 24, true, dissect_ain_ControllingLegTreatment_U);

  return offset;
}


static const ber_sequence_t AuthorizeTerminationArg_sequence[] = {
  { &hf_ain_callingPartyID  , BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_CallingPartyID },
  { &hf_ain_tcm             , BER_CLASS_CON, 51, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Tcm },
  { &hf_ain_controllingLegTreatment, BER_CLASS_CON, 24, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ControllingLegTreatment },
  { &hf_ain_displayText     , BER_CLASS_CON, 26, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_DisplayText },
  { &hf_ain_primaryBillingIndicator, BER_CLASS_CON, 40, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_PrimaryBillingIndicator },
  { &hf_ain_aMAAlternateBillingNumber, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AMAAlternateBillingNumber },
  { &hf_ain_aMABusinessCustomerID, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AMABusinessCustomerID },
  { &hf_ain_aMALineNumberList, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_SEQUENCE_SIZE_1_2_OF_AMALineNumber },
  { &hf_ain_aMAslpID        , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_AMAslpID },
  { &hf_ain_aMADigitsDialedWCList, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_SEQUENCE_SIZE_1_5_OF_AMADigitsDialedWC },
  { &hf_ain_amp1            , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp1 },
  { &hf_ain_amp2            , BER_CLASS_CON, 109, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp2 },
  { &hf_ain_serviceProviderID, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ain_ServiceProviderID },
  { &hf_ain_serviceContext  , BER_CLASS_CON, 83, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ServiceContext },
  { &hf_ain_aMABillingFeature, BER_CLASS_CON, 88, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AMABillingFeature },
  { &hf_ain_aMASequenceNumber, BER_CLASS_CON, 89, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AMASequenceNumber },
  { &hf_ain_extensionParameter, BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_ExtensionParameter },
  { &hf_ain_aMAserviceProviderID, BER_CLASS_CON, 101, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AMAServiceProviderID },
  { &hf_ain_genericName     , BER_CLASS_CON, 33, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_GenericName },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_AuthorizeTerminationArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AuthorizeTerminationArg_sequence, hf_index, ett_ain_AuthorizeTerminationArg);

  return offset;
}


static const ber_sequence_t CancelResourceEventArg_sequence[] = {
  { &hf_ain_amp1            , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp1 },
  { &hf_ain_amp2            , BER_CLASS_CON, 109, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp2 },
  { &hf_ain_serviceProviderID, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ain_ServiceProviderID },
  { &hf_ain_serviceContext  , BER_CLASS_CON, 83, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ServiceContext },
  { &hf_ain_extensionParameter, BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_ExtensionParameter },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_CancelResourceEventArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CancelResourceEventArg_sequence, hf_index, ett_ain_CancelResourceEventArg);

  return offset;
}



static int
dissect_ain_DPConverter(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 76, true, dissect_ain_BOOLEAN);

  return offset;
}



static int
dissect_ain_AlternateDialingPlanInd(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 115, true, dissect_ain_AINDigits);

  return offset;
}


static const ber_sequence_t CollectInformationArg_sequence[] = {
  { &hf_ain_callingPartyID  , BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_CallingPartyID },
  { &hf_ain_collectedDigits , BER_CLASS_CON, 23, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_CollectedDigits },
  { &hf_ain_dPConverter     , BER_CLASS_CON, 76, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_DPConverter },
  { &hf_ain_primaryBillingIndicator, BER_CLASS_CON, 40, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_PrimaryBillingIndicator },
  { &hf_ain_alternateBillingIndicator, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AlternateBillingIndicator },
  { &hf_ain_secondAlternateBillingIndicator, BER_CLASS_CON, 46, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_SecondAlternateBillingIndicator },
  { &hf_ain_overflowBillingIndicator, BER_CLASS_CON, 38, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_OverflowBillingIndicator },
  { &hf_ain_aMAAlternateBillingNumber, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AMAAlternateBillingNumber },
  { &hf_ain_aMALineNumberList, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_SEQUENCE_SIZE_1_2_OF_AMALineNumber },
  { &hf_ain_aMAslpID        , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_AMAslpID },
  { &hf_ain_aMADigitsDialedWCList, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_SEQUENCE_SIZE_1_5_OF_AMADigitsDialedWC },
  { &hf_ain_amp1            , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp1 },
  { &hf_ain_amp2            , BER_CLASS_CON, 109, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp2 },
  { &hf_ain_serviceProviderID, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ain_ServiceProviderID },
  { &hf_ain_serviceContext  , BER_CLASS_CON, 83, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ServiceContext },
  { &hf_ain_aMABillingFeature, BER_CLASS_CON, 88, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AMABillingFeature },
  { &hf_ain_aMASequenceNumber, BER_CLASS_CON, 89, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AMASequenceNumber },
  { &hf_ain_extensionParameter, BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_ExtensionParameter },
  { &hf_ain_alternateDialingPlanInd, BER_CLASS_CON, 115, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AlternateDialingPlanInd },
  { &hf_ain_aMAserviceProviderID, BER_CLASS_CON, 101, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AMAServiceProviderID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_CollectInformationArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CollectInformationArg_sequence, hf_index, ett_ain_CollectInformationArg);

  return offset;
}



static int
dissect_ain_INTEGER_0_127(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_ain_ResourceType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 45, true, dissect_ain_INTEGER_0_127);

  return offset;
}



static int
dissect_ain_AnnounceElement(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t UninterAnnounceBlock_sequence_of[1] = {
  { &hf_ain_UninterAnnounceBlock_item, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ain_AnnounceElement },
};

static int
dissect_ain_UninterAnnounceBlock(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      UninterAnnounceBlock_sequence_of, hf_index, ett_ain_UninterAnnounceBlock);

  return offset;
}


static const ber_sequence_t InterAnnounceBlock_sequence_of[1] = {
  { &hf_ain_InterAnnounceBlock_item, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ain_AnnounceElement },
};

static int
dissect_ain_InterAnnounceBlock(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      InterAnnounceBlock_sequence_of, hf_index, ett_ain_InterAnnounceBlock);

  return offset;
}


static const ber_sequence_t AnnouncementBlock_sequence[] = {
  { &hf_ain_uninterAnnounceBlock, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_UninterAnnounceBlock },
  { &hf_ain_interAnnounceBlock, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_InterAnnounceBlock },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_AnnouncementBlock(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AnnouncementBlock_sequence, hf_index, ett_ain_AnnouncementBlock);

  return offset;
}



static int
dissect_ain_MaximumDigits(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t AnnouncementDigitBlock_sequence[] = {
  { &hf_ain_maximumDigits   , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ain_MaximumDigits },
  { &hf_ain_uninterAnnounceBlock, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_UninterAnnounceBlock },
  { &hf_ain_interAnnounceBlock, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_InterAnnounceBlock },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_AnnouncementDigitBlock(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AnnouncementDigitBlock_sequence, hf_index, ett_ain_AnnouncementDigitBlock);

  return offset;
}



static int
dissect_ain_FlexParameterBlock(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string ain_StrParameterBlock_U_vals[] = {
  {   0, "announcementBlock" },
  {   1, "announcementDigitBlock" },
  {   2, "flexParameterBlock" },
  { 0, NULL }
};

static const ber_choice_t StrParameterBlock_U_choice[] = {
  {   0, &hf_ain_announcementBlock, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ain_AnnouncementBlock },
  {   1, &hf_ain_announcementDigitBlock, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ain_AnnouncementDigitBlock },
  {   2, &hf_ain_flexParameterBlock, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_ain_FlexParameterBlock },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_StrParameterBlock_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 StrParameterBlock_U_choice, hf_index, ett_ain_StrParameterBlock_U,
                                 NULL);

  return offset;
}



static int
dissect_ain_StrParameterBlock(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 50, true, dissect_ain_StrParameterBlock_U);

  return offset;
}



static int
dissect_ain_NULL(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_ain_DisconnectFlag(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 25, true, dissect_ain_NULL);

  return offset;
}



static int
dissect_ain_DestinationAddress(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 86, true, dissect_ain_AINDigits);

  return offset;
}


static const value_string ain_AMAMeasure_U_vals[] = {
  {   0, "connectTimeRecordedDestinationSSP" },
  {   1, "connectTimeRecordedDestinationSCP" },
  {   2, "connectTimeNotRecorded" },
  { 0, NULL }
};


static int
dissect_ain_AMAMeasure_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_ain_AMAMeasure(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 71, true, dissect_ain_AMAMeasure_U);

  return offset;
}


static const ber_sequence_t ConnectToResourceArg_sequence[] = {
  { &hf_ain_resourceType    , BER_CLASS_CON, 45, BER_FLAGS_NOOWNTAG, dissect_ain_ResourceType },
  { &hf_ain_strParameterBlock, BER_CLASS_CON, 50, BER_FLAGS_NOOWNTAG, dissect_ain_StrParameterBlock },
  { &hf_ain_legID           , BER_CLASS_CON, 132, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_LegID },
  { &hf_ain_disconnectFlag  , BER_CLASS_CON, 25, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_DisconnectFlag },
  { &hf_ain_primaryBillingIndicator, BER_CLASS_CON, 40, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_PrimaryBillingIndicator },
  { &hf_ain_aMAAlternateBillingNumber, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AMAAlternateBillingNumber },
  { &hf_ain_aMABusinessCustomerID, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AMABusinessCustomerID },
  { &hf_ain_aMALineNumberList, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_SEQUENCE_SIZE_1_2_OF_AMALineNumber },
  { &hf_ain_aMAslpID        , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_AMAslpID },
  { &hf_ain_aMADigitsDialedWCList, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_SEQUENCE_SIZE_1_5_OF_AMADigitsDialedWC },
  { &hf_ain_amp1            , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp1 },
  { &hf_ain_amp2            , BER_CLASS_CON, 109, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp2 },
  { &hf_ain_destinationAddress, BER_CLASS_CON, 86, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_DestinationAddress },
  { &hf_ain_dPConverter     , BER_CLASS_CON, 76, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_DPConverter },
  { &hf_ain_aMAMeasure      , BER_CLASS_CON, 71, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AMAMeasure },
  { &hf_ain_serviceProviderID, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ain_ServiceProviderID },
  { &hf_ain_serviceContext  , BER_CLASS_CON, 83, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ServiceContext },
  { &hf_ain_aMABillingFeature, BER_CLASS_CON, 88, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AMABillingFeature },
  { &hf_ain_aMASequenceNumber, BER_CLASS_CON, 89, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AMASequenceNumber },
  { &hf_ain_aMAserviceProviderID, BER_CLASS_CON, 101, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AMAServiceProviderID },
  { &hf_ain_extensionParameter, BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_ExtensionParameter },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_ConnectToResourceArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ConnectToResourceArg_sequence, hf_index, ett_ain_ConnectToResourceArg);

  return offset;
}


static const ber_sequence_t ContinueArg_sequence[] = {
  { &hf_ain_primaryBillingIndicator, BER_CLASS_CON, 40, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_PrimaryBillingIndicator },
  { &hf_ain_aMAAlternateBillingNumber, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AMAAlternateBillingNumber },
  { &hf_ain_aMABusinessCustomerID, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AMABusinessCustomerID },
  { &hf_ain_aMALineNumberList, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_SEQUENCE_SIZE_1_2_OF_AMALineNumber },
  { &hf_ain_aMAslpID        , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_AMAslpID },
  { &hf_ain_aMADigitsDialedWCList, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_SEQUENCE_SIZE_1_5_OF_AMADigitsDialedWC },
  { &hf_ain_amp1            , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp1 },
  { &hf_ain_amp2            , BER_CLASS_CON, 109, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp2 },
  { &hf_ain_serviceProviderID, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ain_ServiceProviderID },
  { &hf_ain_serviceContext  , BER_CLASS_CON, 83, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ServiceContext },
  { &hf_ain_aMABillingFeature, BER_CLASS_CON, 88, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AMABillingFeature },
  { &hf_ain_aMASequenceNumber, BER_CLASS_CON, 89, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AMASequenceNumber },
  { &hf_ain_extensionParameter, BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_ExtensionParameter },
  { &hf_ain_aMAserviceProviderID, BER_CLASS_CON, 101, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AMAServiceProviderID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_ContinueArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ContinueArg_sequence, hf_index, ett_ain_ContinueArg);

  return offset;
}



static int
dissect_ain_INTEGER_1_99(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_ain_NotificationDuration(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 128, true, dissect_ain_INTEGER_1_99);

  return offset;
}



static int
dissect_ain_INTEGER_1_999(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_ain_WakeUpDuration(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 131, true, dissect_ain_INTEGER_1_999);

  return offset;
}



static int
dissect_ain_OSIIndicator(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 129, true, dissect_ain_BOOLEAN);

  return offset;
}


static const ber_sequence_t CreateCallArg_sequence[] = {
  { &hf_ain_calledPartyID   , BER_CLASS_CON, 15, BER_FLAGS_NOOWNTAG, dissect_ain_CalledPartyID },
  { &hf_ain_callingPartyID  , BER_CLASS_CON, 18, BER_FLAGS_NOOWNTAG, dissect_ain_CallingPartyID },
  { &hf_ain_chargeNumber    , BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ChargeNumber },
  { &hf_ain_chargePartyStationType, BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ChargePartyStationType },
  { &hf_ain_carrier         , BER_CLASS_CON, 41, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Carrier },
  { &hf_ain_alternateCarrier, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AlternateCarrier },
  { &hf_ain_secondAlternateCarrier, BER_CLASS_CON, 47, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_SecondAlternateCarrier },
  { &hf_ain_passiveLegTreatment, BER_CLASS_CON, 39, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_PassiveLegTreatment },
  { &hf_ain_genericAddressList, BER_CLASS_CON, 107, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_GenericAddressList },
  { &hf_ain_callingPartyBGID, BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_CallingPartyBGID },
  { &hf_ain_forwardCallIndicator, BER_CLASS_CON, 113, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ForwardCallIndicator },
  { &hf_ain_serviceProviderID, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ain_ServiceProviderID },
  { &hf_ain_serviceContext  , BER_CLASS_CON, 83, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ServiceContext },
  { &hf_ain_carrierUsage    , BER_CLASS_CON, 79, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_CarrierUsage },
  { &hf_ain_controllingLegTreatment, BER_CLASS_CON, 24, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ControllingLegTreatment },
  { &hf_ain_userID          , BER_CLASS_CON, 53, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_UserID },
  { &hf_ain_bearerCapability, BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_BearerCapability },
  { &hf_ain_verticalServiceCode, BER_CLASS_CON, 54, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_VerticalServiceCode },
  { &hf_ain_accessCode      , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AccessCode },
  { &hf_ain_displayText     , BER_CLASS_CON, 26, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_DisplayText },
  { &hf_ain_notificationDuration, BER_CLASS_CON, 128, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_NotificationDuration },
  { &hf_ain_wakeUpDuration  , BER_CLASS_CON, 131, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_WakeUpDuration },
  { &hf_ain_oSIIndicator    , BER_CLASS_CON, 129, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_OSIIndicator },
  { &hf_ain_primaryBillingIndicator, BER_CLASS_CON, 40, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_PrimaryBillingIndicator },
  { &hf_ain_overflowBillingIndicator, BER_CLASS_CON, 38, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_OverflowBillingIndicator },
  { &hf_ain_aMAAlternateBillingNumber, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AMAAlternateBillingNumber },
  { &hf_ain_aMABusinessCustomerID, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AMABusinessCustomerID },
  { &hf_ain_aMALineNumberList, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_SEQUENCE_SIZE_1_2_OF_AMALineNumber },
  { &hf_ain_aMAslpID        , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_AMAslpID },
  { &hf_ain_aMAserviceProviderID, BER_CLASS_CON, 101, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AMAServiceProviderID },
  { &hf_ain_amp1            , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp1 },
  { &hf_ain_amp2            , BER_CLASS_CON, 109, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp2 },
  { &hf_ain_extensionParameter, BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_ExtensionParameter },
  { &hf_ain_prefix          , BER_CLASS_CON, 148, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Prefix },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_CreateCallArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CreateCallArg_sequence, hf_index, ett_ain_CreateCallArg);

  return offset;
}


static const ber_sequence_t CreateCallRes_sequence[] = {
  { &hf_ain_failureCause    , BER_CLASS_CON, 32, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_FailureCause },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_CreateCallRes(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CreateCallRes_sequence, hf_index, ett_ain_CreateCallRes);

  return offset;
}



static int
dissect_ain_RTPReroutingNumber(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 143, true, dissect_ain_AINDigits);

  return offset;
}


static const ber_sequence_t DisconnectArg_sequence[] = {
  { &hf_ain_primaryBillingIndicator, BER_CLASS_CON, 40, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_PrimaryBillingIndicator },
  { &hf_ain_aMAAlternateBillingNumber, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AMAAlternateBillingNumber },
  { &hf_ain_aMABusinessCustomerID, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AMABusinessCustomerID },
  { &hf_ain_aMALineNumberList, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_SEQUENCE_SIZE_1_2_OF_AMALineNumber },
  { &hf_ain_aMAslpID        , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_AMAslpID },
  { &hf_ain_aMADigitsDialedWCList, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_SEQUENCE_SIZE_1_5_OF_AMADigitsDialedWC },
  { &hf_ain_amp1            , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp1 },
  { &hf_ain_amp2            , BER_CLASS_CON, 109, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp2 },
  { &hf_ain_serviceProviderID, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ain_ServiceProviderID },
  { &hf_ain_serviceContext  , BER_CLASS_CON, 83, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ServiceContext },
  { &hf_ain_aMABillingFeature, BER_CLASS_CON, 88, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AMABillingFeature },
  { &hf_ain_aMASequenceNumber, BER_CLASS_CON, 89, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AMASequenceNumber },
  { &hf_ain_extensionParameter, BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_ExtensionParameter },
  { &hf_ain_aMAserviceProviderID, BER_CLASS_CON, 101, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AMAServiceProviderID },
  { &hf_ain_rTPReroutingNumber, BER_CLASS_CON, 143, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_RTPReroutingNumber },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_DisconnectArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DisconnectArg_sequence, hf_index, ett_ain_DisconnectArg);

  return offset;
}



static int
dissect_ain_INTEGER_1_2(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_ain_CsID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 137, true, dissect_ain_INTEGER_1_2);

  return offset;
}



static int
dissect_ain_LampTreatment(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 138, true, dissect_ain_OCTET_STRING_SIZE_2_3);

  return offset;
}


static const ber_sequence_t DisconnectLegArg_sequence[] = {
  { &hf_ain_legID           , BER_CLASS_CON, 132, BER_FLAGS_NOOWNTAG, dissect_ain_LegID },
  { &hf_ain_csID            , BER_CLASS_CON, 137, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_CsID },
  { &hf_ain_passiveLegTreatment, BER_CLASS_CON, 39, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_PassiveLegTreatment },
  { &hf_ain_lampTreatment   , BER_CLASS_CON, 138, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_LampTreatment },
  { &hf_ain_displayText     , BER_CLASS_CON, 26, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_DisplayText },
  { &hf_ain_amp1            , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp1 },
  { &hf_ain_amp2            , BER_CLASS_CON, 109, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp2 },
  { &hf_ain_extensionParameter, BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_ExtensionParameter },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_DisconnectLegArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DisconnectLegArg_sequence, hf_index, ett_ain_DisconnectLegArg);

  return offset;
}


static const ber_sequence_t ForwardCallArg_sequence[] = {
  { &hf_ain_callingPartyID  , BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_CallingPartyID },
  { &hf_ain_chargeNumber    , BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ChargeNumber },
  { &hf_ain_chargePartyStationType, BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ChargePartyStationType },
  { &hf_ain_calledPartyID   , BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_CalledPartyID },
  { &hf_ain_outpulseNumber  , BER_CLASS_CON, 37, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_OutpulseNumber },
  { &hf_ain_tcm             , BER_CLASS_CON, 51, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Tcm },
  { &hf_ain_primaryTrunkGroup, BER_CLASS_CON, 42, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_PrimaryTrunkGroup },
  { &hf_ain_alternateTrunkGroup, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AlternateTrunkGroup },
  { &hf_ain_secondAlternateTrunkGroup, BER_CLASS_CON, 48, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_SecondAlternateTrunkGroup },
  { &hf_ain_carrier         , BER_CLASS_CON, 41, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Carrier },
  { &hf_ain_alternateCarrier, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AlternateCarrier },
  { &hf_ain_secondAlternatecarrier, BER_CLASS_CON, 47, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_SecondAlternateCarrier },
  { &hf_ain_passiveLegTreatment, BER_CLASS_CON, 39, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_PassiveLegTreatment },
  { &hf_ain_primaryBillingIndicator, BER_CLASS_CON, 40, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_PrimaryBillingIndicator },
  { &hf_ain_alternateBillingIndicator, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AlternateBillingIndicator },
  { &hf_ain_secondAlternateBillingIndicator, BER_CLASS_CON, 46, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_SecondAlternateBillingIndicator },
  { &hf_ain_overflowBillingIndicator, BER_CLASS_CON, 38, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_OverflowBillingIndicator },
  { &hf_ain_aMAAlternateBillingNumber, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AMAAlternateBillingNumber },
  { &hf_ain_aMABusinessCustomerID, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AMABusinessCustomerID },
  { &hf_ain_aMALineNumberList, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_SEQUENCE_SIZE_1_2_OF_AMALineNumber },
  { &hf_ain_aMAslpID        , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_AMAslpID },
  { &hf_ain_aMADigitsDialedWCList, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_SEQUENCE_SIZE_1_5_OF_AMADigitsDialedWC },
  { &hf_ain_amp1            , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp1 },
  { &hf_ain_amp2            , BER_CLASS_CON, 109, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp2 },
  { &hf_ain_serviceProviderID, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ain_ServiceProviderID },
  { &hf_ain_serviceContext  , BER_CLASS_CON, 83, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ServiceContext },
  { &hf_ain_aMABillingFeature, BER_CLASS_CON, 88, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AMABillingFeature },
  { &hf_ain_aMASequenceNumber, BER_CLASS_CON, 89, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AMASequenceNumber },
  { &hf_ain_redirectingPartyID, BER_CLASS_CON, 43, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_RedirectingPartyID },
  { &hf_ain_redirectionInformation, BER_CLASS_CON, 44, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_RedirectionInformation },
  { &hf_ain_carrierUsage    , BER_CLASS_CON, 79, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_CarrierUsage },
  { &hf_ain_extensionParameter, BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_ExtensionParameter },
  { &hf_ain_aMAserviceProviderID, BER_CLASS_CON, 101, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AMAServiceProviderID },
  { &hf_ain_prefix          , BER_CLASS_CON, 148, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Prefix },
  { &hf_ain_applyRestrictions, BER_CLASS_CON, 152, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ApplyRestrictions },
  { &hf_ain_displayText     , BER_CLASS_CON, 26, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_DisplayText },
  { &hf_ain_genericName     , BER_CLASS_CON, 33, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_GenericName },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_ForwardCallArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ForwardCallArg_sequence, hf_index, ett_ain_ForwardCallArg);

  return offset;
}


static const ber_sequence_t MergeCallArg_sequence[] = {
  { &hf_ain_displayText     , BER_CLASS_CON, 26, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_DisplayText },
  { &hf_ain_lampTreatment   , BER_CLASS_CON, 138, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_LampTreatment },
  { &hf_ain_amp1            , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp1 },
  { &hf_ain_amp2            , BER_CLASS_CON, 109, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp2 },
  { &hf_ain_aMAAlternateBillingNumber, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AMAAlternateBillingNumber },
  { &hf_ain_aMABusinessCustomerID, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AMABusinessCustomerID },
  { &hf_ain_aMALineNumberList, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_SEQUENCE_SIZE_1_2_OF_AMALineNumber },
  { &hf_ain_aMAslpID        , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_AMAslpID },
  { &hf_ain_aMADigitsDialedWCList, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_SEQUENCE_SIZE_1_5_OF_AMADigitsDialedWC },
  { &hf_ain_serviceProviderID, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ain_ServiceProviderID },
  { &hf_ain_serviceContext  , BER_CLASS_CON, 83, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ServiceContext },
  { &hf_ain_aMABillingFeature, BER_CLASS_CON, 88, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AMABillingFeature },
  { &hf_ain_aMASequenceNumber, BER_CLASS_CON, 89, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AMASequenceNumber },
  { &hf_ain_aMAserviceProviderID, BER_CLASS_CON, 101, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AMAServiceProviderID },
  { &hf_ain_extensionParameter, BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_ExtensionParameter },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_MergeCallArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MergeCallArg_sequence, hf_index, ett_ain_MergeCallArg);

  return offset;
}


static const ber_sequence_t MoveLegArg_sequence[] = {
  { &hf_ain_displayText     , BER_CLASS_CON, 26, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_DisplayText },
  { &hf_ain_lampTreatment   , BER_CLASS_CON, 138, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_LampTreatment },
  { &hf_ain_amp1            , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp1 },
  { &hf_ain_amp2            , BER_CLASS_CON, 109, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp2 },
  { &hf_ain_extensionParameter, BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_ExtensionParameter },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_MoveLegArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MoveLegArg_sequence, hf_index, ett_ain_MoveLegArg);

  return offset;
}


static const ber_sequence_t OfferCallArg_sequence[] = {
  { &hf_ain_callingPartyID  , BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_CallingPartyID },
  { &hf_ain_controllingLegTreatment, BER_CLASS_CON, 24, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ControllingLegTreatment },
  { &hf_ain_displayText     , BER_CLASS_CON, 26, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_DisplayText },
  { &hf_ain_primaryBillingIndicator, BER_CLASS_CON, 40, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_PrimaryBillingIndicator },
  { &hf_ain_aMAAlternateBillingNumber, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AMAAlternateBillingNumber },
  { &hf_ain_aMABusinessCustomerID, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AMABusinessCustomerID },
  { &hf_ain_aMALineNumberList, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_SEQUENCE_SIZE_1_2_OF_AMALineNumber },
  { &hf_ain_aMAslpID        , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_AMAslpID },
  { &hf_ain_aMADigitsDialedWCList, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_SEQUENCE_SIZE_1_5_OF_AMADigitsDialedWC },
  { &hf_ain_amp1            , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp1 },
  { &hf_ain_amp2            , BER_CLASS_CON, 109, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp2 },
  { &hf_ain_serviceProviderID, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ain_ServiceProviderID },
  { &hf_ain_serviceContext  , BER_CLASS_CON, 83, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ServiceContext },
  { &hf_ain_aMABillingFeature, BER_CLASS_CON, 88, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AMABillingFeature },
  { &hf_ain_aMASequenceNumber, BER_CLASS_CON, 89, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AMASequenceNumber },
  { &hf_ain_extensionParameter, BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_ExtensionParameter },
  { &hf_ain_aMAserviceProviderID, BER_CLASS_CON, 101, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AMAServiceProviderID },
  { &hf_ain_genericName     , BER_CLASS_CON, 33, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_GenericName },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_OfferCallArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   OfferCallArg_sequence, hf_index, ett_ain_OfferCallArg);

  return offset;
}


static const ber_sequence_t OriginateCallArg_sequence[] = {
  { &hf_ain_collectedDigits , BER_CLASS_CON, 23, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_CollectedDigits },
  { &hf_ain_dPConverter     , BER_CLASS_CON, 76, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_DPConverter },
  { &hf_ain_alternateDialingPlanInd, BER_CLASS_CON, 115, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AlternateDialingPlanInd },
  { &hf_ain_callingPartyID  , BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_CallingPartyID },
  { &hf_ain_lampTreatment   , BER_CLASS_CON, 138, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_LampTreatment },
  { &hf_ain_controllingLegTreatment, BER_CLASS_CON, 24, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ControllingLegTreatment },
  { &hf_ain_displayText     , BER_CLASS_CON, 26, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_DisplayText },
  { &hf_ain_bearerCapability, BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_BearerCapability },
  { &hf_ain_chargeNumber    , BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ChargeNumber },
  { &hf_ain_chargePartyStationType, BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ChargePartyStationType },
  { &hf_ain_calledPartyID   , BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_CalledPartyID },
  { &hf_ain_outpulseNumber  , BER_CLASS_CON, 37, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_OutpulseNumber },
  { &hf_ain_tcm             , BER_CLASS_CON, 51, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Tcm },
  { &hf_ain_primaryTrunkGroup, BER_CLASS_CON, 42, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_PrimaryTrunkGroup },
  { &hf_ain_alternateTrunkGroup, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AlternateTrunkGroup },
  { &hf_ain_secondAlternateTrunkGroup, BER_CLASS_CON, 48, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_SecondAlternateTrunkGroup },
  { &hf_ain_carrier         , BER_CLASS_CON, 41, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Carrier },
  { &hf_ain_alternateCarrier, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AlternateCarrier },
  { &hf_ain_secondAlternatecarrier, BER_CLASS_CON, 47, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_SecondAlternateCarrier },
  { &hf_ain_passiveLegTreatment, BER_CLASS_CON, 39, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_PassiveLegTreatment },
  { &hf_ain_redirectingPartyID, BER_CLASS_CON, 43, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_RedirectingPartyID },
  { &hf_ain_primaryBillingIndicator, BER_CLASS_CON, 40, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_PrimaryBillingIndicator },
  { &hf_ain_alternateBillingIndicator, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AlternateBillingIndicator },
  { &hf_ain_secondAlternateBillingIndicator, BER_CLASS_CON, 46, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_SecondAlternateBillingIndicator },
  { &hf_ain_overflowBillingIndicator, BER_CLASS_CON, 38, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_OverflowBillingIndicator },
  { &hf_ain_genericAddressList, BER_CLASS_CON, 107, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_GenericAddressList },
  { &hf_ain_forwardCallIndicator, BER_CLASS_CON, 113, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ForwardCallIndicator },
  { &hf_ain_aMAAlternateBillingNumber, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AMAAlternateBillingNumber },
  { &hf_ain_aMABusinessCustomerID, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AMABusinessCustomerID },
  { &hf_ain_aMALineNumberList, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_SEQUENCE_SIZE_1_2_OF_AMALineNumber },
  { &hf_ain_aMAslpID        , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_AMAslpID },
  { &hf_ain_aMADigitsDialedWCList, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_SEQUENCE_SIZE_1_5_OF_AMADigitsDialedWC },
  { &hf_ain_amp1            , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp1 },
  { &hf_ain_amp2            , BER_CLASS_CON, 109, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp2 },
  { &hf_ain_serviceProviderID, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ain_ServiceProviderID },
  { &hf_ain_serviceContext  , BER_CLASS_CON, 83, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ServiceContext },
  { &hf_ain_aMABillingFeature, BER_CLASS_CON, 88, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AMABillingFeature },
  { &hf_ain_aMASequenceNumber, BER_CLASS_CON, 89, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AMASequenceNumber },
  { &hf_ain_carrierUsage    , BER_CLASS_CON, 79, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_CarrierUsage },
  { &hf_ain_networkSpecificFacilities, BER_CLASS_CON, 108, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_NetworkSpecificFacilities },
  { &hf_ain_callingPartyBGID, BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_CallingPartyBGID },
  { &hf_ain_aMAserviceProviderID, BER_CLASS_CON, 101, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AMAServiceProviderID },
  { &hf_ain_extensionParameter, BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_ExtensionParameter },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_OriginateCallArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   OriginateCallArg_sequence, hf_index, ett_ain_OriginateCallArg);

  return offset;
}


static const ber_sequence_t ReconnectArg_sequence[] = {
  { &hf_ain_notificationDuration, BER_CLASS_CON, 128, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_NotificationDuration },
  { &hf_ain_controllingLegTreatment, BER_CLASS_CON, 24, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ControllingLegTreatment },
  { &hf_ain_amp1            , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp1 },
  { &hf_ain_amp2            , BER_CLASS_CON, 109, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp2 },
  { &hf_ain_extensionParameter, BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_ExtensionParameter },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_ReconnectArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ReconnectArg_sequence, hf_index, ett_ain_ReconnectArg);

  return offset;
}


static const ber_sequence_t RES_sendToResource_sequence[] = {
  { &hf_ain_extensionParameter, BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_ExtensionParameter },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_RES_sendToResource(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RES_sendToResource_sequence, hf_index, ett_ain_RES_sendToResource);

  return offset;
}



static int
dissect_ain_AnswerIndicator(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 12, true, dissect_ain_NULL);

  return offset;
}



static int
dissect_ain_ExtendedRinging(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 146, true, dissect_ain_NULL);

  return offset;
}



static int
dissect_ain_INTEGER_0_300(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_ain_TSTRCTimer(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 156, true, dissect_ain_INTEGER_0_300);

  return offset;
}


static const value_string ain_PartyID_U_vals[] = {
  {   0, "callingParty" },
  {   1, "calledParty" },
  {   2, "bothParties" },
  { 0, NULL }
};


static int
dissect_ain_PartyID_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_ain_PartyID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 159, true, dissect_ain_PartyID_U);

  return offset;
}



static int
dissect_ain_PartyOnHold(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 146, true, dissect_ain_NULL);

  return offset;
}


static const ber_sequence_t SendToResourceArg_sequence[] = {
  { &hf_ain_resourceType    , BER_CLASS_CON, 45, BER_FLAGS_NOOWNTAG, dissect_ain_ResourceType },
  { &hf_ain_strParameterBlock, BER_CLASS_CON, 50, BER_FLAGS_NOOWNTAG, dissect_ain_StrParameterBlock },
  { &hf_ain_disconnectFlag  , BER_CLASS_CON, 25, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_DisconnectFlag },
  { &hf_ain_answerIndicator , BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AnswerIndicator },
  { &hf_ain_primaryBillingIndicator, BER_CLASS_CON, 40, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_PrimaryBillingIndicator },
  { &hf_ain_aMAAlternateBillingNumber, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AMAAlternateBillingNumber },
  { &hf_ain_aMABusinessCustomerID, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AMABusinessCustomerID },
  { &hf_ain_aMALineNumberList, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_SEQUENCE_SIZE_1_2_OF_AMALineNumber },
  { &hf_ain_aMAslpID        , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_AMAslpID },
  { &hf_ain_aMADigitsDialedWCList, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_SEQUENCE_SIZE_1_5_OF_AMADigitsDialedWC },
  { &hf_ain_amp1            , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp1 },
  { &hf_ain_amp2            , BER_CLASS_CON, 109, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp2 },
  { &hf_ain_destinationAddress, BER_CLASS_CON, 86, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_DestinationAddress },
  { &hf_ain_dPConverter     , BER_CLASS_CON, 76, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_DPConverter },
  { &hf_ain_aMAMeasure      , BER_CLASS_CON, 71, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AMAMeasure },
  { &hf_ain_serviceProviderID, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ain_ServiceProviderID },
  { &hf_ain_serviceContext  , BER_CLASS_CON, 83, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ServiceContext },
  { &hf_ain_aMABillingFeature, BER_CLASS_CON, 88, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AMABillingFeature },
  { &hf_ain_aMASequenceNumber, BER_CLASS_CON, 89, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AMASequenceNumber },
  { &hf_ain_extensionParameter, BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_ExtensionParameter },
  { &hf_ain_aMAserviceProviderID, BER_CLASS_CON, 101, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AMAServiceProviderID },
  { &hf_ain_extendedRinging , BER_CLASS_CON, 146, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ExtendedRinging },
  { &hf_ain_carrier         , BER_CLASS_CON, 41, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Carrier },
  { &hf_ain_alternateCarrier, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AlternateCarrier },
  { &hf_ain_secondAlternatecarrier, BER_CLASS_CON, 47, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_SecondAlternateCarrier },
  { &hf_ain_carrierUsage    , BER_CLASS_CON, 79, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_CarrierUsage },
  { &hf_ain_chargeNumber    , BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ChargeNumber },
  { &hf_ain_chargePartyStationType, BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ChargePartyStationType },
  { &hf_ain_tSTRCTimer      , BER_CLASS_CON, 156, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_TSTRCTimer },
  { &hf_ain_partyID         , BER_CLASS_CON, 159, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_PartyID },
  { &hf_ain_partyOnHold     , BER_CLASS_CON, 146, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_PartyOnHold },
  { &hf_ain_calledPartyID   , BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_CalledPartyID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_SendToResourceArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SendToResourceArg_sequence, hf_index, ett_ain_SendToResourceArg);

  return offset;
}



static int
dissect_ain_INTEGER_1_300(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_ain_SSPResponseMessageTimerT1(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 166, true, dissect_ain_INTEGER_1_300);

  return offset;
}


static const ber_sequence_t SetTimerArg_sequence[] = {
  { &hf_ain_sSPResponseMessageTimerT1, BER_CLASS_CON, 166, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_SSPResponseMessageTimerT1 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_SetTimerArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SetTimerArg_sequence, hf_index, ett_ain_SetTimerArg);

  return offset;
}


static const ber_sequence_t SplitLegArg_sequence[] = {
  { &hf_ain_legID           , BER_CLASS_CON, 132, BER_FLAGS_NOOWNTAG, dissect_ain_LegID },
  { &hf_ain_displayText     , BER_CLASS_CON, 26, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_DisplayText },
  { &hf_ain_lampTreatment   , BER_CLASS_CON, 138, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_LampTreatment },
  { &hf_ain_amp1            , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp1 },
  { &hf_ain_amp2            , BER_CLASS_CON, 109, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp2 },
  { &hf_ain_extensionParameter, BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_ExtensionParameter },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_SplitLegArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SplitLegArg_sequence, hf_index, ett_ain_SplitLegArg);

  return offset;
}



static int
dissect_ain_ControlCauseIndicator(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 59, true, dissect_ain_OCTET_STRING_SIZE_1);

  return offset;
}


static const value_string ain_GapDuration_U_vals[] = {
  {   1, "no1Second" },
  {   2, "no2Seconds" },
  {   3, "no4Seconds" },
  {   4, "no8Seconds" },
  {   5, "no16Seconds" },
  {   6, "no32Seconds" },
  {   7, "no64Seconds" },
  {   8, "no128Seconds" },
  {   9, "no256Seconds" },
  {  10, "no512Seconds" },
  {  11, "no1024Seconds" },
  {  12, "no2048Seconds" },
  {  13, "infinity" },
  { 0, NULL }
};


static int
dissect_ain_GapDuration_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_ain_GapDuration(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 62, true, dissect_ain_GapDuration_U);

  return offset;
}


static const value_string ain_NationalGapInterval_U_vals[] = {
  {   0, "removeGapControl" },
  {   1, "no0Seconds" },
  {   2, "no010Seconds" },
  {   3, "no025Seconds" },
  {   4, "no050Seconds" },
  {   5, "no1Second" },
  {   6, "no2Seconds" },
  {   7, "no5Seconds" },
  {   8, "no10Seconds" },
  {   9, "no15Seconds" },
  {  10, "no30Seconds" },
  {  11, "no60Seconds" },
  {  12, "no120Seconds" },
  {  13, "no300Seconds" },
  {  14, "no600Seconds" },
  {  15, "stopAllCalls" },
  { 0, NULL }
};


static int
dissect_ain_NationalGapInterval_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_ain_NationalGapInterval(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 63, true, dissect_ain_NationalGapInterval_U);

  return offset;
}


static const value_string ain_PrivateGapInterval_U_vals[] = {
  {   0, "no0Seconds" },
  {   1, "no3Seconds" },
  {   2, "no4Seconds" },
  {   3, "no6Seconds" },
  {   4, "no8Seconds" },
  {   5, "no11Seconds" },
  {   6, "no16Seconds" },
  {   7, "no22Seconds" },
  {   8, "no30Seconds" },
  {   9, "no42Seconds" },
  {  10, "no58Seconds" },
  {  11, "no81Seconds" },
  {  12, "no112Seconds" },
  {  13, "no156Seconds" },
  {  14, "no217Seconds" },
  {  15, "no300Seconds" },
  {  16, "removeGapControl" },
  {  17, "no010Seconds" },
  {  18, "no025Seconds" },
  {  19, "no050Seconds" },
  {  20, "no1Second" },
  {  21, "no2Seconds" },
  { 0, NULL }
};


static int
dissect_ain_PrivateGapInterval_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_ain_PrivateGapInterval(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 64, true, dissect_ain_PrivateGapInterval_U);

  return offset;
}


static const value_string ain_GapInterval_vals[] = {
  {  63, "nationalGapInterval" },
  {  64, "privateGapInterval" },
  { 0, NULL }
};

static const ber_choice_t GapInterval_choice[] = {
  {  63, &hf_ain_nationalGapInterval, BER_CLASS_CON, 63, BER_FLAGS_NOOWNTAG, dissect_ain_NationalGapInterval },
  {  64, &hf_ain_privateGapInterval, BER_CLASS_CON, 64, BER_FLAGS_NOOWNTAG, dissect_ain_PrivateGapInterval },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_GapInterval(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 GapInterval_choice, hf_index, ett_ain_GapInterval,
                                 NULL);

  return offset;
}



static int
dissect_ain_TranslationType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 70, true, dissect_ain_INTEGER_0_255);

  return offset;
}



static int
dissect_ain_GlobalTitleAddress(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 69, true, dissect_ain_OCTET_STRING);

  return offset;
}


static const ber_sequence_t AcgArg_sequence[] = {
  { &hf_ain_controlCauseIndicator, BER_CLASS_CON, 59, BER_FLAGS_NOOWNTAG, dissect_ain_ControlCauseIndicator },
  { &hf_ain_gapDuration     , BER_CLASS_CON, 62, BER_FLAGS_NOOWNTAG, dissect_ain_GapDuration },
  { &hf_ain_gapInterval     , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ain_GapInterval },
  { &hf_ain_translationType , BER_CLASS_CON, 70, BER_FLAGS_NOOWNTAG, dissect_ain_TranslationType },
  { &hf_ain_globalTitleAddress, BER_CLASS_CON, 69, BER_FLAGS_NOOWNTAG, dissect_ain_GlobalTitleAddress },
  { &hf_ain_extensionParameter, BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_ExtensionParameter },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_AcgArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AcgArg_sequence, hf_index, ett_ain_AcgArg);

  return offset;
}


static const ber_sequence_t RES_acgGlobalCtrlRestore_sequence[] = {
  { &hf_ain_extensionParameter, BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_ExtensionParameter },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_RES_acgGlobalCtrlRestore(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RES_acgGlobalCtrlRestore_sequence, hf_index, ett_ain_RES_acgGlobalCtrlRestore);

  return offset;
}


static const value_string ain_ACGGlobalOverride_U_vals[] = {
  {   0, "allItems" },
  {   1, "scpOverloadItems" },
  {   2, "smsInitCntrlExceptZeroGap" },
  {   3, "smsInitCntrl" },
  {   4, "ntmOSInitCntrlExceptZeroGap" },
  {   5, "ntmOSInitCntrl" },
  {   6, "craftInitCntrlExceptZeroGap" },
  {   7, "craftInitCntrl" },
  { 0, NULL }
};


static int
dissect_ain_ACGGlobalOverride_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_ain_ACGGlobalOverride(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 110, true, dissect_ain_ACGGlobalOverride_U);

  return offset;
}


static const ber_sequence_t AcgGlobalCtrlRestoreArg_sequence[] = {
  { &hf_ain_aCGGlobalOverride, BER_CLASS_CON, 110, BER_FLAGS_NOOWNTAG, dissect_ain_ACGGlobalOverride },
  { &hf_ain_extensionParameter, BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_ExtensionParameter },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_AcgGlobalCtrlRestoreArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AcgGlobalCtrlRestoreArg_sequence, hf_index, ett_ain_AcgGlobalCtrlRestoreArg);

  return offset;
}


static const ber_sequence_t AcgOverflowArg_sequence[] = {
  { &hf_ain_controlCauseIndicator, BER_CLASS_CON, 59, BER_FLAGS_NOOWNTAG, dissect_ain_ControlCauseIndicator },
  { &hf_ain_translationType , BER_CLASS_CON, 70, BER_FLAGS_NOOWNTAG, dissect_ain_TranslationType },
  { &hf_ain_globalTitleAddress, BER_CLASS_CON, 69, BER_FLAGS_NOOWNTAG, dissect_ain_GlobalTitleAddress },
  { &hf_ain_extensionParameter, BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_ExtensionParameter },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_AcgOverflowArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AcgOverflowArg_sequence, hf_index, ett_ain_AcgOverflowArg);

  return offset;
}


static const value_string ain_ActResult_U_vals[] = {
  {   0, "transactionClosed" },
  {   1, "transactionOpen" },
  {   2, "deniedProcessOverload" },
  { 0, NULL }
};


static int
dissect_ain_ActResult_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_ain_ActResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 164, true, dissect_ain_ActResult_U);

  return offset;
}


static const ber_sequence_t RES_activityTest_sequence[] = {
  { &hf_ain_actResult       , BER_CLASS_CON, 164, BER_FLAGS_NOOWNTAG, dissect_ain_ActResult },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_RES_activityTest(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RES_activityTest_sequence, hf_index, ett_ain_RES_activityTest);

  return offset;
}



static int
dissect_ain_OCTET_STRING_SIZE_4(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_ain_TransID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 163, true, dissect_ain_OCTET_STRING_SIZE_4);

  return offset;
}


static const ber_sequence_t ActivityTestArg_sequence[] = {
  { &hf_ain_transID         , BER_CLASS_CON, 163, BER_FLAGS_NOOWNTAG, dissect_ain_TransID },
  { &hf_ain_extensionParameter, BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_ExtensionParameter },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_ActivityTestArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ActivityTestArg_sequence, hf_index, ett_ain_ActivityTestArg);

  return offset;
}


static const value_string ain_CallType_U_vals[] = {
  {   0, "noIndication" },
  {   1, "local" },
  {   2, "intraLATAToll" },
  {   3, "interLATAToll" },
  { 0, NULL }
};


static int
dissect_ain_CallType_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_ain_CallType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 165, true, dissect_ain_CallType_U);

  return offset;
}


static const ber_sequence_t RES_callTypeRequest_sequence[] = {
  { &hf_ain_callType        , BER_CLASS_CON, 165, BER_FLAGS_NOOWNTAG, dissect_ain_CallType },
  { &hf_ain_extensionParameter, BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_ExtensionParameter },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_RES_callTypeRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RES_callTypeRequest_sequence, hf_index, ett_ain_RES_callTypeRequest);

  return offset;
}


static const ber_sequence_t CallTypeRequestArg_sequence[] = {
  { &hf_ain_calledPartyID   , BER_CLASS_CON, 15, BER_FLAGS_NOOWNTAG, dissect_ain_CalledPartyID },
  { &hf_ain_callingPartyID  , BER_CLASS_CON, 18, BER_FLAGS_NOOWNTAG, dissect_ain_CallingPartyID },
  { &hf_ain_extensionParameter, BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_ExtensionParameter },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_CallTypeRequestArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CallTypeRequestArg_sequence, hf_index, ett_ain_CallTypeRequestArg);

  return offset;
}


static const value_string ain_CongestionLevel_U_vals[] = {
  {   0, "noCongestion" },
  {   1, "mc1" },
  {   2, "mc2" },
  {   3, "mc3" },
  { 0, NULL }
};


static int
dissect_ain_CongestionLevel_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_ain_CongestionLevel(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 117, true, dissect_ain_CongestionLevel_U);

  return offset;
}



static int
dissect_ain_SignalingPointCode(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 142, true, dissect_ain_OCTET_STRING_SIZE_3);

  return offset;
}



static int
dissect_ain_SubsystemNumber(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 130, true, dissect_ain_INTEGER_0_255);

  return offset;
}


static const ber_sequence_t ControlRequestArg_sequence[] = {
  { &hf_ain_congestionLevel , BER_CLASS_CON, 117, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_CongestionLevel },
  { &hf_ain_gapInterval     , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ain_GapInterval },
  { &hf_ain_translationType , BER_CLASS_CON, 70, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_TranslationType },
  { &hf_ain_globalTitleAddress, BER_CLASS_CON, 69, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_GlobalTitleAddress },
  { &hf_ain_ssignalingPointCode, BER_CLASS_CON, 142, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_SignalingPointCode },
  { &hf_ain_subsystemNumber , BER_CLASS_CON, 130, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_SubsystemNumber },
  { &hf_ain_extensionParameter, BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_ExtensionParameter },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_ControlRequestArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ControlRequestArg_sequence, hf_index, ett_ain_ControlRequestArg);

  return offset;
}


static const ber_sequence_t RES_echoRequest_sequence[] = {
  { &hf_ain_failureCause    , BER_CLASS_CON, 32, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_FailureCause },
  { &hf_ain_extensionParameter, BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_ExtensionParameter },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_RES_echoRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RES_echoRequest_sequence, hf_index, ett_ain_RES_echoRequest);

  return offset;
}


static const value_string ain_ApplicationIndicator_U_vals[] = {
  {   0, "routeToApplicationProcessOrSLP" },
  {   1, "processEchoRequestMessage" },
  { 0, NULL }
};


static int
dissect_ain_ApplicationIndicator_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_ain_ApplicationIndicator(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 90, true, dissect_ain_ApplicationIndicator_U);

  return offset;
}


static const ber_sequence_t EchoRequestArg_sequence[] = {
  { &hf_ain_applicationIndicator, BER_CLASS_CON, 90, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ApplicationIndicator },
  { &hf_ain_serviceContext  , BER_CLASS_CON, 83, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ServiceContext },
  { &hf_ain_extensionParameter, BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_ExtensionParameter },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_EchoRequestArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EchoRequestArg_sequence, hf_index, ett_ain_EchoRequestArg);

  return offset;
}



static int
dissect_ain_OCTET_STRING_SIZE_2_128(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_ain_AMABAFModules(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 95, true, dissect_ain_OCTET_STRING_SIZE_2_128);

  return offset;
}



static int
dissect_ain_AMASetHexABIndicator(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 82, true, dissect_ain_BOOLEAN);

  return offset;
}


static const ber_sequence_t FurnishAMAInformationArg_sequence[] = {
  { &hf_ain_aaMABAFModules  , BER_CLASS_CON, 95, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AMABAFModules },
  { &hf_ain_aMASetHexABIndicator, BER_CLASS_CON, 82, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_AMASetHexABIndicator },
  { &hf_ain_extensionParameter, BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_ExtensionParameter },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_FurnishAMAInformationArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   FurnishAMAInformationArg_sequence, hf_index, ett_ain_FurnishAMAInformationArg);

  return offset;
}


static const value_string ain_FacilityStatus_U_vals[] = {
  {   0, "busy" },
  {   1, "busyInService" },
  {   2, "busyOutOfService" },
  {   3, "idle" },
  {   4, "idleInService" },
  {   5, "idleOutOfService" },
  {   6, "inService" },
  {   7, "outOfService" },
  { 0, NULL }
};


static int
dissect_ain_FacilityStatus_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_ain_FacilityStatus(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 61, true, dissect_ain_FacilityStatus_U);

  return offset;
}



static int
dissect_ain_MonitorTime(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 65, true, dissect_ain_OCTET_STRING_SIZE_3);

  return offset;
}



static int
dissect_ain_INTEGER_1_2047(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_ain_Mlhg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 29, true, dissect_ain_INTEGER_1_2047);

  return offset;
}


static const value_string ain_FacilityGID_vals[] = {
  {  29, "mlhg" },
  { 0, NULL }
};

static const ber_choice_t FacilityGID_choice[] = {
  {  29, &hf_ain_mlhg            , BER_CLASS_CON, 29, BER_FLAGS_NOOWNTAG, dissect_ain_Mlhg },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_FacilityGID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 FacilityGID_choice, hf_index, ett_ain_FacilityGID,
                                 NULL);

  return offset;
}



static int
dissect_ain_FacilityMemberID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 31, true, dissect_ain_INTEGER_1_2047);

  return offset;
}



static int
dissect_ain_ControlEncountered(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 127, true, dissect_ain_OCTET_STRING_SIZE_1);

  return offset;
}


static const ber_sequence_t MonitorForChangeArg_sequence[] = {
  { &hf_ain_facilityStatus  , BER_CLASS_CON, 61, BER_FLAGS_NOOWNTAG, dissect_ain_FacilityStatus },
  { &hf_ain_monitorTime     , BER_CLASS_CON, 65, BER_FLAGS_NOOWNTAG, dissect_ain_MonitorTime },
  { &hf_ain_calledPartyID   , BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_CalledPartyID },
  { &hf_ain_facilityGID     , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ain_FacilityGID },
  { &hf_ain_facilityMemberID, BER_CLASS_CON, 31, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_FacilityMemberID },
  { &hf_ain_bearerCapability, BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_BearerCapability },
  { &hf_ain_amp1            , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp1 },
  { &hf_ain_amp2            , BER_CLASS_CON, 109, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp2 },
  { &hf_ain_extensionParameter, BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_ExtensionParameter },
  { &hf_ain_controlEncountered, BER_CLASS_CON, 127, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ControlEncountered },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_MonitorForChangeArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MonitorForChangeArg_sequence, hf_index, ett_ain_MonitorForChangeArg);

  return offset;
}


static const ber_sequence_t MonitorSuccessArg_sequence[] = {
  { &hf_ain_facilityStatus  , BER_CLASS_CON, 61, BER_FLAGS_NOOWNTAG, dissect_ain_FacilityStatus },
  { &hf_ain_amp1            , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp1 },
  { &hf_ain_amp2            , BER_CLASS_CON, 109, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp2 },
  { &hf_ain_extensionParameter, BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_ExtensionParameter },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_MonitorSuccessArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MonitorSuccessArg_sequence, hf_index, ett_ain_MonitorSuccessArg);

  return offset;
}



static int
dissect_ain_SrhrGroupID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 77, true, dissect_ain_INTEGER_0_32767);

  return offset;
}


static const value_string ain_T_id_vals[] = {
  {  15, "calledPartyID" },
  {  77, "srhrGroupID" },
  { 0, NULL }
};

static const ber_choice_t T_id_choice[] = {
  {  15, &hf_ain_calledPartyID   , BER_CLASS_CON, 15, BER_FLAGS_NOOWNTAG, dissect_ain_CalledPartyID },
  {  77, &hf_ain_srhrGroupID     , BER_CLASS_CON, 77, BER_FLAGS_NOOWNTAG, dissect_ain_SrhrGroupID },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_T_id(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_id_choice, hf_index, ett_ain_T_id,
                                 NULL);

  return offset;
}



static int
dissect_ain_OBJECT_IDENTIFIER(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_ain_EnvelopeEncodingAuthority(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 98, true, dissect_ain_OBJECT_IDENTIFIER);

  return offset;
}



static int
dissect_ain_OCTET_STRING_SIZE_1_180(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_ain_EnvelopContent(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 75, true, dissect_ain_OCTET_STRING_SIZE_1_180);

  return offset;
}



static int
dissect_ain_OCTET_STRING_SIZE_3_75(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_ain_SecurityEnvelope(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 85, true, dissect_ain_OCTET_STRING_SIZE_3_75);

  return offset;
}


static const ber_sequence_t NCADataArg_sequence[] = {
  { &hf_ain_id              , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ain_T_id },
  { &hf_ain_callingPartyID  , BER_CLASS_CON, 18, BER_FLAGS_NOOWNTAG, dissect_ain_CallingPartyID },
  { &hf_ain_envelopeEncodingAuthority, BER_CLASS_CON, 98, BER_FLAGS_NOOWNTAG, dissect_ain_EnvelopeEncodingAuthority },
  { &hf_ain_envelopContent  , BER_CLASS_CON, 75, BER_FLAGS_NOOWNTAG, dissect_ain_EnvelopContent },
  { &hf_ain_securityEnvelope, BER_CLASS_CON, 85, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_SecurityEnvelope },
  { &hf_ain_amp1            , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp1 },
  { &hf_ain_amp2            , BER_CLASS_CON, 109, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp2 },
  { &hf_ain_aCGEncountered  , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ACGEncountered },
  { &hf_ain_extensionParameter, BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_ExtensionParameter },
  { &hf_ain_controlEncountered, BER_CLASS_CON, 127, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ControlEncountered },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_NCADataArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   NCADataArg_sequence, hf_index, ett_ain_NCADataArg);

  return offset;
}


static const ber_sequence_t RES_nCARequest_sequence[] = {
  { &hf_ain_envelopeEncodingAuthority, BER_CLASS_CON, 98, BER_FLAGS_NOOWNTAG, dissect_ain_EnvelopeEncodingAuthority },
  { &hf_ain_envelopContent  , BER_CLASS_CON, 75, BER_FLAGS_NOOWNTAG, dissect_ain_EnvelopContent },
  { &hf_ain_securityEnvelope, BER_CLASS_CON, 85, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_SecurityEnvelope },
  { &hf_ain_amp1            , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp1 },
  { &hf_ain_amp2            , BER_CLASS_CON, 109, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp2 },
  { &hf_ain_extensionParameter, BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_ExtensionParameter },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_RES_nCARequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RES_nCARequest_sequence, hf_index, ett_ain_RES_nCARequest);

  return offset;
}


static const ber_sequence_t NCARequestArg_sequence[] = {
  { &hf_ain_calledPartyID   , BER_CLASS_CON, 15, BER_FLAGS_NOOWNTAG, dissect_ain_CalledPartyID },
  { &hf_ain_callingPartyID  , BER_CLASS_CON, 18, BER_FLAGS_NOOWNTAG, dissect_ain_CallingPartyID },
  { &hf_ain_envelopeEncodingAuthority, BER_CLASS_CON, 98, BER_FLAGS_NOOWNTAG, dissect_ain_EnvelopeEncodingAuthority },
  { &hf_ain_envelopContent  , BER_CLASS_CON, 75, BER_FLAGS_NOOWNTAG, dissect_ain_EnvelopContent },
  { &hf_ain_securityEnvelope, BER_CLASS_CON, 85, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_SecurityEnvelope },
  { &hf_ain_amp1            , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp1 },
  { &hf_ain_amp2            , BER_CLASS_CON, 109, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp2 },
  { &hf_ain_aCGEncountered  , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ACGEncountered },
  { &hf_ain_extensionParameter, BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_ExtensionParameter },
  { &hf_ain_controlEncountered, BER_CLASS_CON, 127, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ControlEncountered },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_NCARequestArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   NCARequestArg_sequence, hf_index, ett_ain_NCARequestArg);

  return offset;
}


static const value_string ain_ActivationStateCode_vals[] = {
  {   0, "off" },
  {   1, "on" },
  { 0, NULL }
};


static int
dissect_ain_ActivationStateCode(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string ain_PrivateDn_vals[] = {
  {   0, "private" },
  { 0, NULL }
};


static int
dissect_ain_PrivateDn(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string ain_Entry2_vals[] = {
  {   1, "dn" },
  {   2, "privateDn" },
  { 0, NULL }
};

static const ber_choice_t Entry2_choice[] = {
  {   1, &hf_ain_dn              , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ain_Dn },
  {   2, &hf_ain_privateDn       , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_ain_PrivateDn },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_Entry2(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Entry2_choice, hf_index, ett_ain_Entry2,
                                 NULL);

  return offset;
}


static const ber_sequence_t EntireList_sequence_of[1] = {
  { &hf_ain_EntireList_item , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ain_Entry2 },
};

static int
dissect_ain_EntireList(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      EntireList_sequence_of, hf_index, ett_ain_EntireList);

  return offset;
}



static int
dissect_ain_Timestamp(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t Incoming_sequence[] = {
  { &hf_ain_aINDigits       , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ain_AINDigits },
  { &hf_ain_timestamp       , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_ain_Timestamp },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_Incoming(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Incoming_sequence, hf_index, ett_ain_Incoming);

  return offset;
}


static const ber_sequence_t Outgoing_sequence[] = {
  { &hf_ain_aINDigits       , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ain_AINDigits },
  { &hf_ain_timestamp       , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_ain_Timestamp },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_Outgoing(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Outgoing_sequence, hf_index, ett_ain_Outgoing);

  return offset;
}


static const ber_sequence_t MemorySlot_sequence[] = {
  { &hf_ain_incoming        , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_Incoming },
  { &hf_ain_outgoing        , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_Outgoing },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_MemorySlot(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MemorySlot_sequence, hf_index, ett_ain_MemorySlot);

  return offset;
}



static int
dissect_ain_ListSize(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_ain_ForwardToDn(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ain_Dn(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_ain_DelayInterval(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static int * const Empty_bits[] = {
  &hf_ain_Empty_entireList,
  &hf_ain_Empty_outgoingmemorySlot,
  &hf_ain_Empty_incomingmemorySlot,
  &hf_ain_Empty_forwardToDn,
  NULL
};

static int
dissect_ain_Empty(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    Empty_bits, 4, hf_index, ett_ain_Empty,
                                    NULL);

  return offset;
}


static const ber_sequence_t InfoProvided_U_sequence[] = {
  { &hf_ain_activationStateCode, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_ActivationStateCode },
  { &hf_ain_entireList      , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_EntireList },
  { &hf_ain_memorySlot_01   , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_MemorySlot },
  { &hf_ain_listSize        , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_ListSize },
  { &hf_ain_forwardToDn     , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_ForwardToDn },
  { &hf_ain_delayInterval   , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_DelayInterval },
  { &hf_ain_empty           , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_Empty },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_InfoProvided_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   InfoProvided_U_sequence, hf_index, ett_ain_InfoProvided_U);

  return offset;
}



static int
dissect_ain_InfoProvided(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 100, true, dissect_ain_InfoProvided_U);

  return offset;
}


static const ber_sequence_t RES_queryRequest_sequence[] = {
  { &hf_ain_amp1            , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp1 },
  { &hf_ain_amp2            , BER_CLASS_CON, 109, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp2 },
  { &hf_ain_extensionParameter, BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_ExtensionParameter },
  { &hf_ain_infoProvided    , BER_CLASS_CON, 100, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_InfoProvided },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_RES_queryRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RES_queryRequest_sequence, hf_index, ett_ain_RES_queryRequest);

  return offset;
}


static const value_string ain_Service1_vals[] = {
  {   0, "messageWaitingIndicator" },
  {   1, "visualMessageWaitingIndicator" },
  {   2, "anonymousCallRejection" },
  {   3, "automaticCallback" },
  {   4, "automaticRecall" },
  {   5, "callScreening" },
  {   6, "outsideCallingAreaAlerting" },
  {   7, "callingIdPresentAndSuppress" },
  {   8, "callWaiting" },
  { 0, NULL }
};


static int
dissect_ain_Service1(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static int * const Request1_bits[] = {
  &hf_ain_Request1_activationStatus,
  NULL
};

static int
dissect_ain_Request1(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    Request1_bits, 1, hf_index, ett_ain_Request1,
                                    NULL);

  return offset;
}


static const ber_sequence_t RequestGroup1_sequence[] = {
  { &hf_ain_service1        , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ain_Service1 },
  { &hf_ain_request1        , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_ain_Request1 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_RequestGroup1(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RequestGroup1_sequence, hf_index, ett_ain_RequestGroup1);

  return offset;
}


static const value_string ain_Service2_vals[] = {
  {   0, "audioMessageWaitingIndicator" },
  { 0, NULL }
};


static int
dissect_ain_Service2(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static int * const Request2_bits[] = {
  &hf_ain_Request2_activationStatus,
  &hf_ain_Request2_delayInterval,
  NULL
};

static int
dissect_ain_Request2(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    Request2_bits, 2, hf_index, ett_ain_Request2,
                                    NULL);

  return offset;
}


static const ber_sequence_t RequestGroup2_sequence[] = {
  { &hf_ain_service2        , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ain_Service2 },
  { &hf_ain_request2        , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_ain_Request2 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_RequestGroup2(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RequestGroup2_sequence, hf_index, ett_ain_RequestGroup2);

  return offset;
}


static const value_string ain_Service3_vals[] = {
  {   0, "distinctiveRingingCallWaiting" },
  {   1, "selectiveCallRejection" },
  { 0, NULL }
};


static int
dissect_ain_Service3(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static int * const Request3_bits[] = {
  &hf_ain_Request3_activationStatus,
  &hf_ain_Request3_entireList,
  &hf_ain_Request3_listSize,
  NULL
};

static int
dissect_ain_Request3(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    Request3_bits, 3, hf_index, ett_ain_Request3,
                                    NULL);

  return offset;
}


static const ber_sequence_t RequestGroup3_sequence[] = {
  { &hf_ain_service3        , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ain_Service3 },
  { &hf_ain_request3        , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_ain_Request3 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_RequestGroup3(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RequestGroup3_sequence, hf_index, ett_ain_RequestGroup3);

  return offset;
}


static const value_string ain_Service4_vals[] = {
  {   0, "callForwardingVariable" },
  {   1, "callForwardingDontAnswer" },
  {   2, "callForwardingBusyLine" },
  { 0, NULL }
};


static int
dissect_ain_Service4(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static int * const Request4_bits[] = {
  &hf_ain_Request4_activationStatus,
  &hf_ain_Request4_forwardingDn,
  NULL
};

static int
dissect_ain_Request4(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    Request4_bits, 2, hf_index, ett_ain_Request4,
                                    NULL);

  return offset;
}


static const ber_sequence_t RequestGroup4_sequence[] = {
  { &hf_ain_service4        , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ain_Service4 },
  { &hf_ain_request4        , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_ain_Request4 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_RequestGroup4(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RequestGroup4_sequence, hf_index, ett_ain_RequestGroup4);

  return offset;
}


static const value_string ain_Service5_vals[] = {
  {   0, "selectiveCallAcceptance" },
  {   1, "selectiveCallForwarding" },
  { 0, NULL }
};


static int
dissect_ain_Service5(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static int * const Request5_bits[] = {
  &hf_ain_Request5_activationStatus,
  &hf_ain_Request5_forwardingDn,
  &hf_ain_Request5_entireList,
  &hf_ain_Request5_listSize,
  NULL
};

static int
dissect_ain_Request5(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    Request5_bits, 4, hf_index, ett_ain_Request5,
                                    NULL);

  return offset;
}


static const ber_sequence_t RequestGroup5_sequence[] = {
  { &hf_ain_service5        , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ain_Service5 },
  { &hf_ain_request5        , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_ain_Request5 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_RequestGroup5(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RequestGroup5_sequence, hf_index, ett_ain_RequestGroup5);

  return offset;
}


static const value_string ain_Service6_vals[] = {
  {   0, "ringControl" },
  { 0, NULL }
};


static int
dissect_ain_Service6(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static int * const Request6_bits[] = {
  &hf_ain_Request6_delayInterval,
  NULL
};

static int
dissect_ain_Request6(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    Request6_bits, 1, hf_index, ett_ain_Request6,
                                    NULL);

  return offset;
}


static const ber_sequence_t RequestGroup6_sequence[] = {
  { &hf_ain_service6        , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ain_Service6 },
  { &hf_ain_request6        , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_ain_Request6 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_RequestGroup6(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RequestGroup6_sequence, hf_index, ett_ain_RequestGroup6);

  return offset;
}


static const value_string ain_RequestGroups_vals[] = {
  {   1, "requestGroup1" },
  {   2, "requestGroup2" },
  {   3, "requestGroup3" },
  {   4, "requestGroup4" },
  {   5, "requestGroup5" },
  {   6, "requestGroup6" },
  { 0, NULL }
};

static const ber_choice_t RequestGroups_choice[] = {
  {   1, &hf_ain_requestGroup1   , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ain_RequestGroup1 },
  {   2, &hf_ain_requestGroup2   , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_ain_RequestGroup2 },
  {   3, &hf_ain_requestGroup3   , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_ain_RequestGroup3 },
  {   4, &hf_ain_requestGroup4   , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_ain_RequestGroup4 },
  {   5, &hf_ain_requestGroup5   , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_ain_RequestGroup5 },
  {   6, &hf_ain_requestGroup6   , BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_ain_RequestGroup6 },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_RequestGroups(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 RequestGroups_choice, hf_index, ett_ain_RequestGroups,
                                 NULL);

  return offset;
}


static int * const RequestMemorySlot_bits[] = {
  &hf_ain_RequestMemorySlot_incoming,
  &hf_ain_RequestMemorySlot_outgoing,
  NULL
};

static int
dissect_ain_RequestMemorySlot(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    RequestMemorySlot_bits, 2, hf_index, ett_ain_RequestMemorySlot,
                                    NULL);

  return offset;
}


static const ber_sequence_t ProvideInfo_U_sequence[] = {
  { &hf_ain_requestGroups   , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ain_RequestGroups },
  { &hf_ain_requestMemorySlot, BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_RequestMemorySlot },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_ProvideInfo_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ProvideInfo_U_sequence, hf_index, ett_ain_ProvideInfo_U);

  return offset;
}



static int
dissect_ain_ProvideInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 114, true, dissect_ain_ProvideInfo_U);

  return offset;
}


static const ber_sequence_t QueryRequestArg_sequence[] = {
  { &hf_ain_userID          , BER_CLASS_CON, 53, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_UserID },
  { &hf_ain_amp1            , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp1 },
  { &hf_ain_amp2            , BER_CLASS_CON, 109, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp2 },
  { &hf_ain_extensionParameter, BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_ExtensionParameter },
  { &hf_ain_controlEncountered, BER_CLASS_CON, 127, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ControlEncountered },
  { &hf_ain_provideInfo     , BER_CLASS_CON, 114, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ProvideInfo },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_QueryRequestArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   QueryRequestArg_sequence, hf_index, ett_ain_QueryRequestArg);

  return offset;
}


static int * const EDPRequest_U_bits[] = {
  &hf_ain_EDPRequest_U_oCalledPartyBusy,
  &hf_ain_EDPRequest_U_oNoAnswer,
  &hf_ain_EDPRequest_U_oTermSeized,
  &hf_ain_EDPRequest_U_oAnswer,
  &hf_ain_EDPRequest_U_tBusy,
  &hf_ain_EDPRequest_U_tNoAnswer,
  &hf_ain_EDPRequest_U_termResourceAvailable,
  &hf_ain_EDPRequest_U_tAnswer,
  &hf_ain_EDPRequest_U_networkBusy,
  &hf_ain_EDPRequest_U_oSuspended,
  &hf_ain_EDPRequest_U_oDisconnectCalled,
  &hf_ain_EDPRequest_U_oDisconnect,
  &hf_ain_EDPRequest_U_oAbandon,
  &hf_ain_EDPRequest_U_featureActivator,
  &hf_ain_EDPRequest_U_switchHookFlash,
  &hf_ain_EDPRequest_U_success,
  &hf_ain_EDPRequest_U_tDisconnect,
  &hf_ain_EDPRequest_U_timeout,
  &hf_ain_EDPRequest_U_originationAttempt,
  &hf_ain_EDPRequest_U_oDTMFEntered,
  &hf_ain_EDPRequest_U_tDTMFEntered,
  NULL
};

static int
dissect_ain_EDPRequest_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    EDPRequest_U_bits, 21, hf_index, ett_ain_EDPRequest_U,
                                    NULL);

  return offset;
}



static int
dissect_ain_EDPRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 92, true, dissect_ain_EDPRequest_U);

  return offset;
}


static int * const EDPNotification_U_bits[] = {
  &hf_ain_EDPNotification_U_oCalledPartyBusy,
  &hf_ain_EDPNotification_U_oNoAnswer,
  &hf_ain_EDPNotification_U_oTermSeized,
  &hf_ain_EDPNotification_U_oAnswer,
  &hf_ain_EDPNotification_U_tBusy,
  &hf_ain_EDPNotification_U_tNoAnswer,
  &hf_ain_EDPNotification_U_termResourceAvailable,
  &hf_ain_EDPNotification_U_tAnswer,
  &hf_ain_EDPNotification_U_networkBusy,
  &hf_ain_EDPNotification_U_oSuspended,
  &hf_ain_EDPNotification_U_oDisconnectCalled,
  &hf_ain_EDPNotification_U_oDisconnect,
  &hf_ain_EDPNotification_U_oAbandon,
  &hf_ain_EDPNotification_U_featureActivator,
  &hf_ain_EDPNotification_U_switchHookFlash,
  &hf_ain_EDPNotification_U_success,
  &hf_ain_EDPNotification_U_tDisconnect,
  &hf_ain_EDPNotification_U_timeout,
  &hf_ain_EDPNotification_U_originationAttempt,
  &hf_ain_EDPNotification_U_oDTMFEntered,
  &hf_ain_EDPNotification_U_tDTMFEntered,
  NULL
};

static int
dissect_ain_EDPNotification_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    EDPNotification_U_bits, 21, hf_index, ett_ain_EDPNotification_U,
                                    NULL);

  return offset;
}



static int
dissect_ain_EDPNotification(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 93, true, dissect_ain_EDPNotification_U);

  return offset;
}



static int
dissect_ain_INTEGER_1_120(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_ain_ONoAnswerTimer(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 91, true, dissect_ain_INTEGER_1_120);

  return offset;
}



static int
dissect_ain_TNoAnswerTimer(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 99, true, dissect_ain_INTEGER_1_120);

  return offset;
}



static int
dissect_ain_IntervalTime(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_ain_LocalSSPTime(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_ain_AbsoluteSCPTime(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string ain_TimeoutTimer_U_vals[] = {
  {   0, "intervalTime" },
  {   1, "localSSPTime" },
  {   2, "absoluteSCPTime" },
  { 0, NULL }
};

static const ber_choice_t TimeoutTimer_U_choice[] = {
  {   0, &hf_ain_intervalTime    , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ain_IntervalTime },
  {   1, &hf_ain_localSSPTime    , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ain_LocalSSPTime },
  {   2, &hf_ain_absoluteSCPTime , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_ain_AbsoluteSCPTime },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_TimeoutTimer_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 TimeoutTimer_U_choice, hf_index, ett_ain_TimeoutTimer_U,
                                 NULL);

  return offset;
}



static int
dissect_ain_TimeoutTimer(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 139, true, dissect_ain_TimeoutTimer_U);

  return offset;
}



static int
dissect_ain_ODTMFDigitsString(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 154, true, dissect_ain_AINDigits);

  return offset;
}



static int
dissect_ain_INTEGER_1_4(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_ain_ODTMFNumberOfDigits(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 155, true, dissect_ain_INTEGER_1_4);

  return offset;
}



static int
dissect_ain_TDTMFDigitString(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 157, true, dissect_ain_AINDigits);

  return offset;
}



static int
dissect_ain_TDTMFNumberOfDigits(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 158, true, dissect_ain_INTEGER_1_4);

  return offset;
}


static const ber_sequence_t RequestReportBCMEventArg_sequence[] = {
  { &hf_ain_eDPRequest      , BER_CLASS_CON, 92, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_EDPRequest },
  { &hf_ain_eDPNotification , BER_CLASS_CON, 93, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_EDPNotification },
  { &hf_ain_oNoAnswerTimer  , BER_CLASS_CON, 91, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ONoAnswerTimer },
  { &hf_ain_tNoAnswerTimer  , BER_CLASS_CON, 99, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_TNoAnswerTimer },
  { &hf_ain_extensionParameter, BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_ExtensionParameter },
  { &hf_ain_timeoutTimer    , BER_CLASS_CON, 139, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_TimeoutTimer },
  { &hf_ain_oDTMFDigitsString, BER_CLASS_CON, 154, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ODTMFDigitsString },
  { &hf_ain_oDTMFNumberOfDigits, BER_CLASS_CON, 155, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ODTMFNumberOfDigits },
  { &hf_ain_tDTMFDigitString, BER_CLASS_CON, 157, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_TDTMFDigitString },
  { &hf_ain_tDTMFNumberOfDigits, BER_CLASS_CON, 158, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_TDTMFNumberOfDigits },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_RequestReportBCMEventArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RequestReportBCMEventArg_sequence, hf_index, ett_ain_RequestReportBCMEventArg);

  return offset;
}


static const value_string ain_StatusCause_U_vals[] = {
  {   0, "statusMatch" },
  {   1, "timeOut" },
  {   2, "error" },
  { 0, NULL }
};


static int
dissect_ain_StatusCause_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_ain_StatusCause(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 66, true, dissect_ain_StatusCause_U);

  return offset;
}


static const ber_sequence_t StatusReportedArg_sequence[] = {
  { &hf_ain_facilityStatus  , BER_CLASS_CON, 61, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_FacilityStatus },
  { &hf_ain_statusCause     , BER_CLASS_CON, 66, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_StatusCause },
  { &hf_ain_failureCause    , BER_CLASS_CON, 32, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_FailureCause },
  { &hf_ain_amp1            , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp1 },
  { &hf_ain_amp2            , BER_CLASS_CON, 109, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp2 },
  { &hf_ain_extensionParameter, BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_ExtensionParameter },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_StatusReportedArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   StatusReportedArg_sequence, hf_index, ett_ain_StatusReportedArg);

  return offset;
}



static int
dissect_ain_EchoData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 60, true, dissect_ain_OCTET_STRING_SIZE_6);

  return offset;
}



static int
dissect_ain_TerminationIndicator(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 67, true, dissect_ain_OCTET_STRING_SIZE_1);

  return offset;
}



static int
dissect_ain_ConnectTime(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 58, true, dissect_ain_OCTET_STRING_SIZE_5);

  return offset;
}


static const ber_sequence_t TerminationNotificationArg_sequence[] = {
  { &hf_ain_echoData        , BER_CLASS_CON, 60, BER_FLAGS_NOOWNTAG, dissect_ain_EchoData },
  { &hf_ain_terminationIndicator, BER_CLASS_CON, 67, BER_FLAGS_NOOWNTAG, dissect_ain_TerminationIndicator },
  { &hf_ain_connectTime     , BER_CLASS_CON, 58, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ConnectTime },
  { &hf_ain_busyCause       , BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_BusyCause },
  { &hf_ain_amp1            , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp1 },
  { &hf_ain_amp2            , BER_CLASS_CON, 109, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp2 },
  { &hf_ain_extensionParameter, BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_ExtensionParameter },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_TerminationNotificationArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TerminationNotificationArg_sequence, hf_index, ett_ain_TerminationNotificationArg);

  return offset;
}


static const value_string ain_ResultCause_U_vals[] = {
  {   0, "confServiceActivated" },
  {   1, "confServiceDeactivatedorCancelled" },
  {   2, "confAnonymousEntryAdded" },
  {   3, "confPublicEntryAdded" },
  {   4, "confAnonymousEntryRemoved" },
  {   5, "confPublicEntryRemoved" },
  {   6, "confAllAnonymousEntriesRemoved" },
  {   7, "confAllEntriesRemoved" },
  {   8, "confForwardingDnSet" },
  {   9, "confForwardingDnCleared" },
  {  10, "confDelayIntervalUpdated" },
  {  11, "confInterdigitTimerOn" },
  {  12, "confInterdigitTimerOff" },
  {  13, "confDPConverterOn" },
  {  14, "confDPConverterOff" },
  {  15, "deniedServiceAlreadyActive" },
  {  16, "deniedServiceNotActivated" },
  {  17, "deniedInvalidForwardingDn" },
  {  18, "deniedPermanentPresentationPrivate" },
  {  19, "deniedPermanentPresentationPublic" },
  {  20, "deniedListIsEmpty" },
  {  21, "deniedListIsFull" },
  {  22, "deniedAnonymousDnAlreadyOnList" },
  {  23, "deniedPublicDnAlreadyOnList" },
  {  24, "deniedNoMatch" },
  {  25, "deniedDnNotOnList" },
  {  26, "deniedIncomingMemorySlotEmpty" },
  {  27, "deniedUnsuccessfulUpdate" },
  { 0, NULL }
};


static int
dissect_ain_ResultCause_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_ain_ResultCause(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 151, true, dissect_ain_ResultCause_U);

  return offset;
}


static const ber_sequence_t RES_update_sequence[] = {
  { &hf_ain_amp1            , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp1 },
  { &hf_ain_amp2            , BER_CLASS_CON, 109, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp2 },
  { &hf_ain_extensionParameter, BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_ExtensionParameter },
  { &hf_ain_resultCause     , BER_CLASS_CON, 151, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ResultCause },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_RES_update(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RES_update_sequence, hf_index, ett_ain_RES_update);

  return offset;
}


static const value_string ain_Ct_vals[] = {
  {   0, "voicebandInformation" },
  {   1, "circuitModeData" },
  { 0, NULL }
};


static int
dissect_ain_Ct(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t DnCtID_sequence[] = {
  { &hf_ain_dn              , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ain_Dn },
  { &hf_ain_ct              , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_ain_Ct },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_DnCtID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DnCtID_sequence, hf_index, ett_ain_DnCtID);

  return offset;
}



static int
dissect_ain_LocalSSPID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_ain_PublicDialingPlanID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_ain_PRIOfficeEquipmentID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_ain_BasicBusinessGroupID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_ain_BasicBusinessGroupDialingPlanID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_ain_AFRPatternID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_ain_OfficeEquipmentID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const value_string ain_SSPUserResourceID_vals[] = {
  {   1, "dn" },
  {   2, "dnCtID" },
  {   3, "spid" },
  {   4, "trunkGroupID" },
  {   5, "localSSPID" },
  {   6, "publicDialingPlanID" },
  {   7, "pRIOfficeEquipmentID" },
  {   8, "basicBusinessGroupID" },
  {   9, "basicBusinessGroupDialingPlanID" },
  {  10, "aFRPatternID" },
  {  11, "officeEquipmentID" },
  { 0, NULL }
};

static const ber_choice_t SSPUserResourceID_choice[] = {
  {   1, &hf_ain_dn              , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ain_Dn },
  {   2, &hf_ain_dnCtID          , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_ain_DnCtID },
  {   3, &hf_ain_spid            , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_ain_Spid },
  {   4, &hf_ain_trunkGroupID    , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_ain_TrunkGroupID },
  {   5, &hf_ain_localSSPID      , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_ain_LocalSSPID },
  {   6, &hf_ain_publicDialingPlanID, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_ain_PublicDialingPlanID },
  {   7, &hf_ain_pRIOfficeEquipmentID, BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_ain_PRIOfficeEquipmentID },
  {   8, &hf_ain_basicBusinessGroupID, BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_ain_BasicBusinessGroupID },
  {   9, &hf_ain_basicBusinessGroupDialingPlanID, BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_ain_BasicBusinessGroupDialingPlanID },
  {  10, &hf_ain_aFRPatternID    , BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_ain_AFRPatternID },
  {  11, &hf_ain_officeEquipmentID, BER_CLASS_CON, 11, BER_FLAGS_IMPLTAG, dissect_ain_OfficeEquipmentID },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_SSPUserResourceID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 SSPUserResourceID_choice, hf_index, ett_ain_SSPUserResourceID,
                                 NULL);

  return offset;
}



static int
dissect_ain_DPNumber(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_ain_TriggerItemSubnumber(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t TriggerItemID_sequence[] = {
  { &hf_ain_dPNumber        , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ain_DPNumber },
  { &hf_ain_triggerItemSubnumber, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_ain_TriggerItemSubnumber },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_TriggerItemID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TriggerItemID_sequence, hf_index, ett_ain_TriggerItemID);

  return offset;
}


static const value_string ain_PotentialUse_vals[] = {
  {   0, "notApplicable" },
  {   1, "callForwarding" },
  { 0, NULL }
};


static int
dissect_ain_PotentialUse(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_ain_PRIDS1ID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_ain_PRIDS0ID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t ISDNBChannelID_sequence[] = {
  { &hf_ain_pRIDS1ID        , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_PRIDS1ID },
  { &hf_ain_pRIDS0ID        , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_PRIDS0ID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_ISDNBChannelID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ISDNBChannelID_sequence, hf_index, ett_ain_ISDNBChannelID);

  return offset;
}


static const value_string ain_SSPUserResourceSubID_vals[] = {
  {   1, "aFRPatternID" },
  {   2, "basicBusinessGroupDialingPlanID" },
  {   3, "iSDNBChannelID" },
  { 0, NULL }
};

static const ber_choice_t SSPUserResourceSubID_choice[] = {
  {   1, &hf_ain_aFRPatternID    , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ain_AFRPatternID },
  {   2, &hf_ain_basicBusinessGroupDialingPlanID, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_ain_BasicBusinessGroupDialingPlanID },
  {   3, &hf_ain_iSDNBChannelID  , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_ain_ISDNBChannelID },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_SSPUserResourceSubID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 SSPUserResourceSubID_choice, hf_index, ett_ain_SSPUserResourceSubID,
                                 NULL);

  return offset;
}


static const ber_sequence_t TriggerItemAssignment_U_sequence[] = {
  { &hf_ain_sSPUserResourceID, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_ain_SSPUserResourceID },
  { &hf_ain_triggerItemID   , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_ain_TriggerItemID },
  { &hf_ain_activationStateCode, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_ActivationStateCode },
  { &hf_ain_potentialUse    , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_PotentialUse },
  { &hf_ain_sSPUserResourceSubID, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_ain_SSPUserResourceSubID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_TriggerItemAssignment_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TriggerItemAssignment_U_sequence, hf_index, ett_ain_TriggerItemAssignment_U);

  return offset;
}



static int
dissect_ain_TriggerItemAssignment(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 102, true, dissect_ain_TriggerItemAssignment_U);

  return offset;
}


static const value_string ain_Action1_vals[] = {
  {   2, "activationStateCode" },
  { 0, NULL }
};

static const ber_choice_t Action1_choice[] = {
  {   2, &hf_ain_activationStateCode, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_ain_ActivationStateCode },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_Action1(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Action1_choice, hf_index, ett_ain_Action1,
                                 NULL);

  return offset;
}


static const ber_sequence_t UpdateGroup1_sequence[] = {
  { &hf_ain_service1        , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ain_Service1 },
  { &hf_ain_action1         , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ain_Action1 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_UpdateGroup1(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   UpdateGroup1_sequence, hf_index, ett_ain_UpdateGroup1);

  return offset;
}


static const value_string ain_Action2_vals[] = {
  {   2, "activationStateCode" },
  {   3, "delayInterval" },
  { 0, NULL }
};

static const ber_choice_t Action2_choice[] = {
  {   2, &hf_ain_activationStateCode, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_ain_ActivationStateCode },
  {   3, &hf_ain_delayInterval   , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_ain_DelayInterval },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_Action2(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Action2_choice, hf_index, ett_ain_Action2,
                                 NULL);

  return offset;
}


static const ber_sequence_t UpdateGroup2_sequence[] = {
  { &hf_ain_service2        , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ain_Service2 },
  { &hf_ain_action2         , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ain_Action2 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_UpdateGroup2(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   UpdateGroup2_sequence, hf_index, ett_ain_UpdateGroup2);

  return offset;
}



static int
dissect_ain_SpeedCallingCode(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const value_string ain_MemorySlot1_vals[] = {
  {   0, "incoming" },
  { 0, NULL }
};


static int
dissect_ain_MemorySlot1(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string ain_Entry_vals[] = {
  {   1, "dn" },
  {   2, "speedCallingCode" },
  {   3, "memorySlot" },
  { 0, NULL }
};

static const ber_choice_t Entry_choice[] = {
  {   1, &hf_ain_dn              , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ain_Dn },
  {   2, &hf_ain_speedCallingCode, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_ain_SpeedCallingCode },
  {   3, &hf_ain_memorySlot      , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_ain_MemorySlot1 },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_Entry(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Entry_choice, hf_index, ett_ain_Entry,
                                 NULL);

  return offset;
}


static const value_string ain_EditListType_vals[] = {
  {   0, "addListElement" },
  {   1, "deleteListElement" },
  { 0, NULL }
};


static int
dissect_ain_EditListType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t EditSpecificEntry_sequence[] = {
  { &hf_ain_entry           , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ain_Entry },
  { &hf_ain_editListType    , BER_CLASS_CON, 105, BER_FLAGS_IMPLTAG, dissect_ain_EditListType },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_EditSpecificEntry(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EditSpecificEntry_sequence, hf_index, ett_ain_EditSpecificEntry);

  return offset;
}


static const value_string ain_EditAllEntries_vals[] = {
  {   0, "deleteAllEntries" },
  {   1, "deleteAllPrivateEntries" },
  { 0, NULL }
};


static int
dissect_ain_EditAllEntries(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string ain_Action3_vals[] = {
  {   2, "activationStateCode" },
  {   3, "editSpecificEntry" },
  {   4, "editAllEntries" },
  { 0, NULL }
};

static const ber_choice_t Action3_choice[] = {
  {   2, &hf_ain_activationStateCode, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_ain_ActivationStateCode },
  {   3, &hf_ain_editSpecificEntry, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_ain_EditSpecificEntry },
  {   4, &hf_ain_editAllEntries  , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_ain_EditAllEntries },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_Action3(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Action3_choice, hf_index, ett_ain_Action3,
                                 NULL);

  return offset;
}


static const ber_sequence_t UpdateGroup3_sequence[] = {
  { &hf_ain_service3        , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ain_Service3 },
  { &hf_ain_action3         , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ain_Action3 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_UpdateGroup3(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   UpdateGroup3_sequence, hf_index, ett_ain_UpdateGroup3);

  return offset;
}


static const value_string ain_Set_vals[] = {
  {   1, "dn" },
  {   4, "speedCallingCode" },
  { 0, NULL }
};

static const ber_choice_t Set_choice[] = {
  {   1, &hf_ain_dn              , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ain_Dn },
  {   4, &hf_ain_speedCallingCode, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_ain_SpeedCallingCode },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_Set(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Set_choice, hf_index, ett_ain_Set,
                                 NULL);

  return offset;
}


static const value_string ain_Clear_vals[] = {
  {   0, "remove" },
  { 0, NULL }
};


static int
dissect_ain_Clear(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string ain_ForwardingDn_vals[] = {
  {   0, "set" },
  {   1, "clear" },
  { 0, NULL }
};

static const ber_choice_t ForwardingDn_choice[] = {
  {   0, &hf_ain_set             , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_ain_Set },
  {   1, &hf_ain_clear           , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_ain_Clear },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_ForwardingDn(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ForwardingDn_choice, hf_index, ett_ain_ForwardingDn,
                                 NULL);

  return offset;
}


static const value_string ain_Action4_vals[] = {
  {   0, "activationStateCode" },
  {   1, "forwardingDn" },
  { 0, NULL }
};

static const ber_choice_t Action4_choice[] = {
  {   0, &hf_ain_activationStateCode, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_ain_ActivationStateCode },
  {   1, &hf_ain_forwardingDn    , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_ain_ForwardingDn },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_Action4(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Action4_choice, hf_index, ett_ain_Action4,
                                 NULL);

  return offset;
}


static const ber_sequence_t UpdateGroup4_sequence[] = {
  { &hf_ain_service4        , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ain_Service4 },
  { &hf_ain_action4         , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ain_Action4 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_UpdateGroup4(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   UpdateGroup4_sequence, hf_index, ett_ain_UpdateGroup4);

  return offset;
}


static const value_string ain_Action5_vals[] = {
  {   2, "activationStateCode" },
  {   3, "forwardingDn" },
  {   4, "editSpecificEntry" },
  {   5, "editAllEntries" },
  { 0, NULL }
};

static const ber_choice_t Action5_choice[] = {
  {   2, &hf_ain_activationStateCode, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_ain_ActivationStateCode },
  {   3, &hf_ain_forwardingDn    , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_ain_ForwardingDn },
  {   4, &hf_ain_editSpecificEntry, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_ain_EditSpecificEntry },
  {   5, &hf_ain_editAllEntries  , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_ain_EditAllEntries },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_Action5(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Action5_choice, hf_index, ett_ain_Action5,
                                 NULL);

  return offset;
}


static const ber_sequence_t UpdateGroup5_sequence[] = {
  { &hf_ain_service5        , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ain_Service5 },
  { &hf_ain_action5         , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ain_Action5 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_UpdateGroup5(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   UpdateGroup5_sequence, hf_index, ett_ain_UpdateGroup5);

  return offset;
}


static const value_string ain_Action6_vals[] = {
  {   2, "delayInterval" },
  { 0, NULL }
};

static const ber_choice_t Action6_choice[] = {
  {   2, &hf_ain_delayInterval   , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_ain_DelayInterval },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_Action6(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Action6_choice, hf_index, ett_ain_Action6,
                                 NULL);

  return offset;
}


static const ber_sequence_t UpdateGroup6_sequence[] = {
  { &hf_ain_service6        , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ain_Service6 },
  { &hf_ain_action6         , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ain_Action6 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_UpdateGroup6(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   UpdateGroup6_sequence, hf_index, ett_ain_UpdateGroup6);

  return offset;
}


static const value_string ain_Service7_vals[] = {
  {   0, "callingNumberDeliveryBlocking" },
  {   1, "callingNameDeliveryBlocking" },
  { 0, NULL }
};


static int
dissect_ain_Service7(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string ain_Toggle_vals[] = {
  {   0, "presentationStatusValue" },
  { 0, NULL }
};


static int
dissect_ain_Toggle(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string ain_Action7_vals[] = {
  {   2, "toggle" },
  { 0, NULL }
};

static const ber_choice_t Action7_choice[] = {
  {   2, &hf_ain_toggle          , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_ain_Toggle },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_Action7(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Action7_choice, hf_index, ett_ain_Action7,
                                 NULL);

  return offset;
}


static const ber_sequence_t UpdateGroup7_sequence[] = {
  { &hf_ain_service7        , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ain_Service7 },
  { &hf_ain_action7         , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ain_Action7 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_UpdateGroup7(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   UpdateGroup7_sequence, hf_index, ett_ain_UpdateGroup7);

  return offset;
}


static const value_string ain_Service8_vals[] = {
  {   0, "customerOriginatedTrace" },
  {   1, "cancelCallWaiting" },
  { 0, NULL }
};


static int
dissect_ain_Service8(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string ain_Invoke8_vals[] = {
  {   0, "on" },
  { 0, NULL }
};


static int
dissect_ain_Invoke8(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string ain_Action8_vals[] = {
  {   2, "invoke" },
  { 0, NULL }
};

static const ber_choice_t Action8_choice[] = {
  {   2, &hf_ain_action8_invoke  , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_ain_Invoke8 },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_Action8(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Action8_choice, hf_index, ett_ain_Action8,
                                 NULL);

  return offset;
}


static const ber_sequence_t UpdateGroup8_sequence[] = {
  { &hf_ain_service8        , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ain_Service8 },
  { &hf_ain_action8         , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ain_Action8 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_UpdateGroup8(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   UpdateGroup8_sequence, hf_index, ett_ain_UpdateGroup8);

  return offset;
}


static const value_string ain_Service9_vals[] = {
  {   0, "speedCalling" },
  { 0, NULL }
};


static int
dissect_ain_Service9(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t ChangeList_sequence[] = {
  { &hf_ain_dn              , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ain_Dn },
  { &hf_ain_speedCallingCode, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_ain_SpeedCallingCode },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_ChangeList(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ChangeList_sequence, hf_index, ett_ain_ChangeList);

  return offset;
}


static const value_string ain_Action9_vals[] = {
  {   2, "changeList" },
  { 0, NULL }
};

static const ber_choice_t Action9_choice[] = {
  {   2, &hf_ain_changeList      , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_ain_ChangeList },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_Action9(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Action9_choice, hf_index, ett_ain_Action9,
                                 NULL);

  return offset;
}


static const ber_sequence_t UpdateGroup9_sequence[] = {
  { &hf_ain_service9        , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ain_Service9 },
  { &hf_ain_action9         , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ain_Action9 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_UpdateGroup9(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   UpdateGroup9_sequence, hf_index, ett_ain_UpdateGroup9);

  return offset;
}


static const value_string ain_UpdateGroups_vals[] = {
  {   2, "updateGroup1" },
  {   3, "updateGroup2" },
  {   4, "updateGroup3" },
  {   5, "updateGroup4" },
  {   6, "updateGroup5" },
  {   7, "updateGroup6" },
  {   8, "updateGroup7" },
  {   9, "updateGroup8" },
  {  10, "updateGroup9" },
  { 0, NULL }
};

static const ber_choice_t UpdateGroups_choice[] = {
  {   2, &hf_ain_updateGroup1    , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_ain_UpdateGroup1 },
  {   3, &hf_ain_updateGroup2    , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_ain_UpdateGroup2 },
  {   4, &hf_ain_updateGroup3    , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_ain_UpdateGroup3 },
  {   5, &hf_ain_updateGroup4    , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_ain_UpdateGroup4 },
  {   6, &hf_ain_updateGroup5    , BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_ain_UpdateGroup5 },
  {   7, &hf_ain_updateGroup6    , BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_ain_UpdateGroup6 },
  {   8, &hf_ain_updateGroup7    , BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_ain_UpdateGroup7 },
  {   9, &hf_ain_updateGroup8    , BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_ain_UpdateGroup8 },
  {  10, &hf_ain_updateGroup9    , BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_ain_UpdateGroup9 },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_UpdateGroups(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 UpdateGroups_choice, hf_index, ett_ain_UpdateGroups,
                                 NULL);

  return offset;
}



static int
dissect_ain_CancelInterdigitTimer(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ain_ActivationStateCode(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t SSPUserResource_U_sequence[] = {
  { &hf_ain_sSPUserResourceID, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_ain_SSPUserResourceID },
  { &hf_ain_serviceProviderID, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ain_ServiceProviderID },
  { &hf_ain_updateGroups    , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ain_UpdateGroups },
  { &hf_ain_oNoAnswerTimer  , BER_CLASS_CON, 91, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ONoAnswerTimer },
  { &hf_ain_tNoAnswerTimer  , BER_CLASS_CON, 99, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_TNoAnswerTimer },
  { &hf_ain_displayText     , BER_CLASS_CON, 26, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_DisplayText },
  { &hf_ain_dPConverter     , BER_CLASS_CON, 76, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_DPConverter },
  { &hf_ain_cancelInterdigitTimer, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_CancelInterdigitTimer },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_SSPUserResource_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SSPUserResource_U_sequence, hf_index, ett_ain_SSPUserResource_U);

  return offset;
}



static int
dissect_ain_SSPUserResource(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 103, true, dissect_ain_SSPUserResource_U);

  return offset;
}



static int
dissect_ain_SrhrID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ain_AINDigits(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t SrhrGroup_U_sequence[] = {
  { &hf_ain_srhrGroupID     , BER_CLASS_CON, 77, BER_FLAGS_NOOWNTAG, dissect_ain_SrhrGroupID },
  { &hf_ain_srhrID          , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_SrhrID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_SrhrGroup_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SrhrGroup_U_sequence, hf_index, ett_ain_SrhrGroup_U);

  return offset;
}



static int
dissect_ain_SrhrGroup(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 104, true, dissect_ain_SrhrGroup_U);

  return offset;
}



static int
dissect_ain_NtdIndirectID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ain_SSPUserResourceID(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string ain_NtdID_vals[] = {
  {   1, "ntdIndirectID" },
  { 0, NULL }
};

static const ber_choice_t NtdID_choice[] = {
  {   1, &hf_ain_ntdIndirectID   , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ain_NtdIndirectID },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_NtdID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 NtdID_choice, hf_index, ett_ain_NtdID,
                                 NULL);

  return offset;
}


static const ber_sequence_t NetworkTestDesignator_U_sequence[] = {
  { &hf_ain_ntdID           , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ain_NtdID },
  { &hf_ain_amp1            , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp1 },
  { &hf_ain_amp2            , BER_CLASS_CON, 109, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp2 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_NetworkTestDesignator_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   NetworkTestDesignator_U_sequence, hf_index, ett_ain_NetworkTestDesignator_U);

  return offset;
}



static int
dissect_ain_NetworkTestDesignator(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 97, true, dissect_ain_NetworkTestDesignator_U);

  return offset;
}


static const value_string ain_OperationsMonitoredItemID_vals[] = {
  {   1, "sSPUserResourceID" },
  { 0, NULL }
};

static const ber_choice_t OperationsMonitoredItemID_choice[] = {
  {   1, &hf_ain_sSPUserResourceID, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ain_SSPUserResourceID },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_OperationsMonitoredItemID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 OperationsMonitoredItemID_choice, hf_index, ett_ain_OperationsMonitoredItemID,
                                 NULL);

  return offset;
}


static const ber_sequence_t OperationsMonitoringAssignment_U_sequence[] = {
  { &hf_ain_operationsMonitoredItemID, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ain_OperationsMonitoredItemID },
  { &hf_ain_activationStateCode, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_ActivationStateCode },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_OperationsMonitoringAssignment_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   OperationsMonitoringAssignment_U_sequence, hf_index, ett_ain_OperationsMonitoringAssignment_U);

  return offset;
}



static int
dissect_ain_OperationsMonitoringAssignment(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 118, true, dissect_ain_OperationsMonitoringAssignment_U);

  return offset;
}


static const value_string ain_AdministrableObject_vals[] = {
  { 102, "triggerItemAssignment" },
  { 103, "sSPUserResource" },
  { 104, "srhrGroup" },
  {  97, "networkTestDesignator" },
  { 118, "operationsMonitoringAssignment" },
  { 0, NULL }
};

static const ber_choice_t AdministrableObject_choice[] = {
  { 102, &hf_ain_triggerItemAssignment, BER_CLASS_CON, 102, BER_FLAGS_NOOWNTAG, dissect_ain_TriggerItemAssignment },
  { 103, &hf_ain_sSPUserResource , BER_CLASS_CON, 103, BER_FLAGS_NOOWNTAG, dissect_ain_SSPUserResource },
  { 104, &hf_ain_srhrGroup       , BER_CLASS_CON, 104, BER_FLAGS_NOOWNTAG, dissect_ain_SrhrGroup },
  {  97, &hf_ain_networkTestDesignator, BER_CLASS_CON, 97, BER_FLAGS_NOOWNTAG, dissect_ain_NetworkTestDesignator },
  { 118, &hf_ain_operationsMonitoringAssignment, BER_CLASS_CON, 118, BER_FLAGS_NOOWNTAG, dissect_ain_OperationsMonitoringAssignment },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_AdministrableObject(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 AdministrableObject_choice, hf_index, ett_ain_AdministrableObject,
                                 NULL);

  return offset;
}


static const ber_sequence_t UpdateArg_sequence[] = {
  { &hf_ain_administrableObject, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ain_AdministrableObject },
  { &hf_ain_editListType    , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_EditListType },
  { &hf_ain_amp1            , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp1 },
  { &hf_ain_amp2            , BER_CLASS_CON, 109, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_Amp2 },
  { &hf_ain_extensionParameter, BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_ExtensionParameter },
  { &hf_ain_controlEncountered, BER_CLASS_CON, 127, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ControlEncountered },
  { &hf_ain_aMAslpID        , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_AMAslpID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_UpdateArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   UpdateArg_sequence, hf_index, ett_ain_UpdateArg);

  return offset;
}


static const ber_sequence_t RES_updateRequest_sequence[] = {
  { &hf_ain_failureCause    , BER_CLASS_CON, 32, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_FailureCause },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_RES_updateRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RES_updateRequest_sequence, hf_index, ett_ain_RES_updateRequest);

  return offset;
}



static int
dissect_ain_TriggerCriteriaFlag(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 68, true, dissect_ain_OCTET_STRING_SIZE_2);

  return offset;
}


static const ber_sequence_t UpdateRequestArg_sequence[] = {
  { &hf_ain_userID          , BER_CLASS_CON, 53, BER_FLAGS_NOOWNTAG, dissect_ain_UserID },
  { &hf_ain_triggerCriteriaFlag, BER_CLASS_CON, 68, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_TriggerCriteriaFlag },
  { &hf_ain_bearerCapability, BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_BearerCapability },
  { &hf_ain_controlEncountered, BER_CLASS_CON, 127, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ControlEncountered },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_UpdateRequestArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   UpdateRequestArg_sequence, hf_index, ett_ain_UpdateRequestArg);

  return offset;
}


static const value_string ain_ErrorCause_U_vals[] = {
  {   0, "erroneousDataValue" },
  {   1, "missingConditionalParameter" },
  {   2, "responseMessageTimerExpired" },
  {   3, "unexpectedCommunication" },
  {   4, "unexpectedMessage" },
  {   5, "unexpectedMessageSequence" },
  {   6, "unexpectedParameterSequence" },
  { 0, NULL }
};


static int
dissect_ain_ErrorCause_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_ain_ErrorCause(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 56, true, dissect_ain_ErrorCause_U);

  return offset;
}



static int
dissect_ain_INTEGER(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string ain_TimerUpdated_U_vals[] = {
  {   0, "success" },
  {   1, "failure" },
  {   2, "transaction-already-closed" },
  { 0, NULL }
};


static int
dissect_ain_TimerUpdated_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_ain_TimerUpdated(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 167, true, dissect_ain_TimerUpdated_U);

  return offset;
}



static int
dissect_ain_OCTET_STRING_SIZE_1_5(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_ain_FailureCauseData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 112, true, dissect_ain_OCTET_STRING_SIZE_1_5);

  return offset;
}


static const value_string ain_Parms_vals[] = {
  {   0, "accessCode" },
  {   1, "aCGEncountered" },
  {   2, "alternateBillingIndicator" },
  {   3, "alternateCarrier" },
  {   4, "alternateTrunkGroup" },
  {   5, "aMAAlternateBillingNumber" },
  {   6, "aMABusinessCustomerID" },
  {   7, "aMAslpID" },
  {   8, "amp1" },
  {   9, "amp2" },
  {  10, "answerIndicator" },
  {  11, "bearerCapability" },
  {  12, "busyCause" },
  {  13, "calledPartyID" },
  {  14, "calledPartyStationType" },
  {  15, "callingGeodeticLocation" },
  {  16, "callingPartyBGID" },
  {  17, "callingPartyID" },
  {  18, "callType" },
  {  19, "chargeNumber" },
  {  20, "chargePartyStationType" },
  {  21, "clearCause" },
  {  22, "collectedAddressInfo" },
  {  23, "collectedDigits" },
  {  24, "controllingLegTreatment" },
  {  25, "disconnectFlag" },
  {  26, "displayText" },
  {  27, "dTMFDigitsDetected" },
  {  28, "facilityGID" },
  {  29, "facilityMemberID" },
  {  30, "failureCause" },
  {  31, "genericName" },
  {  32, "lata" },
  {  33, "oDTMFDigitsString" },
  {  34, "oDTMFNumberofDigits" },
  {  35, "originalCalledPartyID" },
  {  36, "outpulseNumber" },
  {  37, "overflowBillingIndicator" },
  {  38, "passiveLegTreatment" },
  {  39, "partyID" },
  {  40, "partyOnHold" },
  {  41, "primaryBillingIndicator" },
  {  42, "carrier" },
  {  43, "primaryTrunkGroup" },
  {  44, "redirectingPartyID" },
  {  45, "redirectionInformation" },
  {  46, "resourceType" },
  {  47, "secondAlternateBillingIndicator" },
  {  48, "secondAlternateCarrier" },
  {  49, "secondAlternateTrunkGroup" },
  {  50, "spid" },
  {  51, "sSPResponseMessageTimerT1" },
  {  52, "strParameterBlock" },
  {  53, "tcm" },
  {  54, "tDTMFDigitString" },
  {  55, "tDTMFNumberOfDigits" },
  {  56, "timerUpdated" },
  {  57, "triggerCriteriaType" },
  {  58, "triggerInformation" },
  {  59, "userID" },
  {  60, "verticalServiceCode" },
  {  61, "connectTime" },
  {  62, "controlCauseIndicator" },
  {  63, "echoData" },
  {  64, "facilityStatus" },
  {  65, "gapDuration" },
  {  66, "gapInterval" },
  {  67, "globalTitleAddress" },
  {  68, "monitorTime" },
  {  69, "statusCause" },
  {  70, "terminationIndicator" },
  {  71, "translationType" },
  {  72, "triggerCriteriaFlag" },
  {  73, "tSTRCTimer" },
  {  74, "aMAMeasure" },
  {  75, "aMAMeasurement" },
  {  76, "clearCauseData" },
  {  77, "envelopContent" },
  {  78, "iPReturnBlock" },
  {  79, "sap" },
  {  80, "aMASetHexABIndicator" },
  {  81, "serviceContext" },
  {  82, "extensionParameter" },
  {  83, "securityEnvelope" },
  {  84, "destinationAddress" },
  {  85, "derviceProviderID" },
  {  86, "aMABillingFeature" },
  {  87, "aMASequenceNumber" },
  {  88, "applicationIndicator" },
  {  89, "oNoAnswerTimer" },
  {  90, "eDPRequest" },
  {  91, "eDPNotification" },
  {  92, "busyType" },
  {  93, "aMABAFModules" },
  {  94, "sTRConnection" },
  {  95, "errorCause" },
  {  96, "resultCause" },
  {  97, "cTRConnection" },
  {  98, "rTPReroutingNumber" },
  {  99, "rTPServiceIndicator" },
  { 100, "administrableObject" },
  { 101, "envelopeEncodingAuthority" },
  { 102, "tNoAnswerTimer" },
  { 103, "editListType" },
  { 104, "aCGGlobalOverride" },
  { 105, "notificationIndicator" },
  { 106, "aMALineNumber" },
  { 107, "aMADigitsDialedWC" },
  { 108, "carrierUsage" },
  { 109, "closeCause" },
  { 110, "dPConverter" },
  { 111, "failureCauseData" },
  { 112, "genericAddress" },
  { 113, "srhrGroupID" },
  { 114, "genericAddressList" },
  { 115, "networkSpecificFacilities" },
  { 116, "forwardCallIndicator" },
  { 117, "alternateDialingPlanInd" },
  { 118, "disconnectCause" },
  { 119, "aMAServiceProviderID" },
  { 120, "congestionLevel" },
  { 121, "controlEncountered" },
  { 122, "infoProvided" },
  { 123, "provideInfo" },
  { 124, "signalingPointCode" },
  { 125, "subsystemNumber" },
  { 126, "notificationDuration" },
  { 127, "wakeUpDuration" },
  { 128, "oSIIndicator" },
  { 129, "legID" },
  { 130, "ccID" },
  { 131, "bCMType" },
  { 132, "pointInCall" },
  { 133, "featureActivatorID" },
  { 134, "csID" },
  { 135, "lampTreatment" },
  { 136, "timeoutTimer" },
  { 137, "transID" },
  { 138, "actResult" },
  { 139, "extendedRinging" },
  { 140, "jurisdictionInformation" },
  { 141, "prefix" },
  { 142, "genericDigitsList" },
  { 143, "applyRestrictions" },
  { 0, NULL }
};

static const ber_choice_t Parms_choice[] = {
  {   0, &hf_ain_accessCode      , BER_CLASS_CON, 1, BER_FLAGS_NOOWNTAG, dissect_ain_AccessCode },
  {   1, &hf_ain_aCGEncountered  , BER_CLASS_CON, 2, BER_FLAGS_NOOWNTAG, dissect_ain_ACGEncountered },
  {   2, &hf_ain_alternateBillingIndicator, BER_CLASS_CON, 3, BER_FLAGS_NOOWNTAG, dissect_ain_AlternateBillingIndicator },
  {   3, &hf_ain_alternateCarrier, BER_CLASS_CON, 4, BER_FLAGS_NOOWNTAG, dissect_ain_AlternateCarrier },
  {   4, &hf_ain_alternateTrunkGroup, BER_CLASS_CON, 5, BER_FLAGS_NOOWNTAG, dissect_ain_AlternateTrunkGroup },
  {   5, &hf_ain_aMAAlternateBillingNumber, BER_CLASS_CON, 6, BER_FLAGS_NOOWNTAG, dissect_ain_AMAAlternateBillingNumber },
  {   6, &hf_ain_aMABusinessCustomerID, BER_CLASS_CON, 7, BER_FLAGS_NOOWNTAG, dissect_ain_AMABusinessCustomerID },
  {   7, &hf_ain_aMAslpID        , BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_ain_AMAslpID },
  {   8, &hf_ain_amp1            , BER_CLASS_CON, 11, BER_FLAGS_NOOWNTAG, dissect_ain_Amp1 },
  {   9, &hf_ain_amp2            , BER_CLASS_CON, 109, BER_FLAGS_NOOWNTAG, dissect_ain_Amp2 },
  {  10, &hf_ain_answerIndicator , BER_CLASS_CON, 12, BER_FLAGS_NOOWNTAG, dissect_ain_AnswerIndicator },
  {  11, &hf_ain_bearerCapability, BER_CLASS_CON, 13, BER_FLAGS_NOOWNTAG, dissect_ain_BearerCapability },
  {  12, &hf_ain_busyCause       , BER_CLASS_CON, 14, BER_FLAGS_NOOWNTAG, dissect_ain_BusyCause },
  {  13, &hf_ain_calledPartyID   , BER_CLASS_CON, 15, BER_FLAGS_NOOWNTAG, dissect_ain_CalledPartyID },
  {  14, &hf_ain_calledPartyStationType, BER_CLASS_CON, 16, BER_FLAGS_NOOWNTAG, dissect_ain_CalledPartyStationType },
  {  15, &hf_ain_callingGeodeticLocation, BER_CLASS_CON, 162, BER_FLAGS_NOOWNTAG, dissect_ain_CallingGeodeticLocation },
  {  16, &hf_ain_callingPartyBGID, BER_CLASS_CON, 17, BER_FLAGS_NOOWNTAG, dissect_ain_CallingPartyBGID },
  {  17, &hf_ain_callingPartyID  , BER_CLASS_CON, 18, BER_FLAGS_NOOWNTAG, dissect_ain_CallingPartyID },
  {  18, &hf_ain_callType        , BER_CLASS_CON, 165, BER_FLAGS_NOOWNTAG, dissect_ain_CallType },
  {  19, &hf_ain_chargeNumber    , BER_CLASS_CON, 19, BER_FLAGS_NOOWNTAG, dissect_ain_ChargeNumber },
  {  20, &hf_ain_chargePartyStationType, BER_CLASS_CON, 20, BER_FLAGS_NOOWNTAG, dissect_ain_ChargePartyStationType },
  {  21, &hf_ain_clearCause      , BER_CLASS_CON, 21, BER_FLAGS_NOOWNTAG, dissect_ain_ClearCause },
  {  22, &hf_ain_collectedAddressInfo, BER_CLASS_CON, 22, BER_FLAGS_NOOWNTAG, dissect_ain_CollectedAddressInfo },
  {  23, &hf_ain_collectedDigits , BER_CLASS_CON, 23, BER_FLAGS_NOOWNTAG, dissect_ain_CollectedDigits },
  {  24, &hf_ain_controllingLegTreatment, BER_CLASS_CON, 24, BER_FLAGS_NOOWNTAG, dissect_ain_ControllingLegTreatment },
  {  25, &hf_ain_disconnectFlag  , BER_CLASS_CON, 25, BER_FLAGS_NOOWNTAG, dissect_ain_DisconnectFlag },
  {  26, &hf_ain_displayText     , BER_CLASS_CON, 26, BER_FLAGS_NOOWNTAG, dissect_ain_DisplayText },
  {  27, &hf_ain_dTMFDigitsDetected, BER_CLASS_CON, 153, BER_FLAGS_NOOWNTAG, dissect_ain_DTMFDigitsDetected },
  {  28, &hf_ain_facilityGID     , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_ain_FacilityGID },
  {  29, &hf_ain_facilityMemberID, BER_CLASS_CON, 31, BER_FLAGS_NOOWNTAG, dissect_ain_FacilityMemberID },
  {  30, &hf_ain_failureCause    , BER_CLASS_CON, 32, BER_FLAGS_NOOWNTAG, dissect_ain_FailureCause },
  {  31, &hf_ain_genericName     , BER_CLASS_CON, 33, BER_FLAGS_NOOWNTAG, dissect_ain_GenericName },
  {  32, &hf_ain_lata            , BER_CLASS_CON, 35, BER_FLAGS_NOOWNTAG, dissect_ain_Lata },
  {  33, &hf_ain_oDTMFDigitsString, BER_CLASS_CON, 154, BER_FLAGS_NOOWNTAG, dissect_ain_ODTMFDigitsString },
  {  34, &hf_ain_oDTMFNumberofDigits, BER_CLASS_CON, 155, BER_FLAGS_NOOWNTAG, dissect_ain_ODTMFNumberOfDigits },
  {  35, &hf_ain_originalCalledPartyID, BER_CLASS_CON, 36, BER_FLAGS_NOOWNTAG, dissect_ain_OriginalCalledPartyID },
  {  36, &hf_ain_outpulseNumber  , BER_CLASS_CON, 37, BER_FLAGS_NOOWNTAG, dissect_ain_OutpulseNumber },
  {  37, &hf_ain_overflowBillingIndicator, BER_CLASS_CON, 38, BER_FLAGS_NOOWNTAG, dissect_ain_OverflowBillingIndicator },
  {  38, &hf_ain_passiveLegTreatment, BER_CLASS_CON, 39, BER_FLAGS_NOOWNTAG, dissect_ain_PassiveLegTreatment },
  {  39, &hf_ain_partyID         , BER_CLASS_CON, 159, BER_FLAGS_NOOWNTAG, dissect_ain_PartyID },
  {  40, &hf_ain_partyOnHold     , BER_CLASS_CON, 146, BER_FLAGS_NOOWNTAG, dissect_ain_PartyOnHold },
  {  41, &hf_ain_primaryBillingIndicator, BER_CLASS_CON, 40, BER_FLAGS_NOOWNTAG, dissect_ain_PrimaryBillingIndicator },
  {  42, &hf_ain_carrier         , BER_CLASS_CON, 41, BER_FLAGS_NOOWNTAG, dissect_ain_Carrier },
  {  43, &hf_ain_primaryTrunkGroup, BER_CLASS_CON, 42, BER_FLAGS_NOOWNTAG, dissect_ain_PrimaryTrunkGroup },
  {  44, &hf_ain_redirectingPartyID, BER_CLASS_CON, 43, BER_FLAGS_NOOWNTAG, dissect_ain_RedirectingPartyID },
  {  45, &hf_ain_redirectionInformation, BER_CLASS_CON, 44, BER_FLAGS_NOOWNTAG, dissect_ain_RedirectionInformation },
  {  46, &hf_ain_resourceType    , BER_CLASS_CON, 45, BER_FLAGS_NOOWNTAG, dissect_ain_ResourceType },
  {  47, &hf_ain_secondAlternateBillingIndicator, BER_CLASS_CON, 46, BER_FLAGS_NOOWNTAG, dissect_ain_SecondAlternateBillingIndicator },
  {  48, &hf_ain_secondAlternateCarrier, BER_CLASS_CON, 47, BER_FLAGS_NOOWNTAG, dissect_ain_SecondAlternateCarrier },
  {  49, &hf_ain_secondAlternateTrunkGroup, BER_CLASS_CON, 48, BER_FLAGS_NOOWNTAG, dissect_ain_SecondAlternateTrunkGroup },
  {  50, &hf_ain_spid            , BER_CLASS_CON, 49, BER_FLAGS_NOOWNTAG, dissect_ain_Spid },
  {  51, &hf_ain_sSPResponseMessageTimerT1, BER_CLASS_CON, 166, BER_FLAGS_NOOWNTAG, dissect_ain_SSPResponseMessageTimerT1 },
  {  52, &hf_ain_strParameterBlock, BER_CLASS_CON, 50, BER_FLAGS_NOOWNTAG, dissect_ain_StrParameterBlock },
  {  53, &hf_ain_tcm             , BER_CLASS_CON, 51, BER_FLAGS_NOOWNTAG, dissect_ain_Tcm },
  {  54, &hf_ain_tDTMFDigitString, BER_CLASS_CON, 157, BER_FLAGS_NOOWNTAG, dissect_ain_TDTMFDigitString },
  {  55, &hf_ain_tDTMFNumberOfDigits, BER_CLASS_CON, 158, BER_FLAGS_NOOWNTAG, dissect_ain_TDTMFNumberOfDigits },
  {  56, &hf_ain_timerUpdated    , BER_CLASS_CON, 167, BER_FLAGS_NOOWNTAG, dissect_ain_TimerUpdated },
  {  57, &hf_ain_triggerCriteriaType, BER_CLASS_CON, 52, BER_FLAGS_NOOWNTAG, dissect_ain_TriggerCriteriaType },
  {  58, &hf_ain_triggerInformation, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ain_TriggerInformation },
  {  59, &hf_ain_userID          , BER_CLASS_CON, 53, BER_FLAGS_NOOWNTAG, dissect_ain_UserID },
  {  60, &hf_ain_verticalServiceCode, BER_CLASS_CON, 54, BER_FLAGS_NOOWNTAG, dissect_ain_VerticalServiceCode },
  {  61, &hf_ain_connectTime     , BER_CLASS_CON, 58, BER_FLAGS_NOOWNTAG, dissect_ain_ConnectTime },
  {  62, &hf_ain_controlCauseIndicator, BER_CLASS_CON, 59, BER_FLAGS_NOOWNTAG, dissect_ain_ControlCauseIndicator },
  {  63, &hf_ain_echoData        , BER_CLASS_CON, 60, BER_FLAGS_NOOWNTAG, dissect_ain_EchoData },
  {  64, &hf_ain_facilityStatus  , BER_CLASS_CON, 61, BER_FLAGS_NOOWNTAG, dissect_ain_FacilityStatus },
  {  65, &hf_ain_gapDuration     , BER_CLASS_CON, 62, BER_FLAGS_NOOWNTAG, dissect_ain_GapDuration },
  {  66, &hf_ain_gapInterval     , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_ain_GapInterval },
  {  67, &hf_ain_globalTitleAddress, BER_CLASS_CON, 69, BER_FLAGS_NOOWNTAG, dissect_ain_GlobalTitleAddress },
  {  68, &hf_ain_monitorTime     , BER_CLASS_CON, 65, BER_FLAGS_NOOWNTAG, dissect_ain_MonitorTime },
  {  69, &hf_ain_statusCause     , BER_CLASS_CON, 66, BER_FLAGS_NOOWNTAG, dissect_ain_StatusCause },
  {  70, &hf_ain_terminationIndicator, BER_CLASS_CON, 67, BER_FLAGS_NOOWNTAG, dissect_ain_TerminationIndicator },
  {  71, &hf_ain_translationType , BER_CLASS_CON, 70, BER_FLAGS_NOOWNTAG, dissect_ain_TranslationType },
  {  72, &hf_ain_triggerCriteriaFlag, BER_CLASS_CON, 68, BER_FLAGS_NOOWNTAG, dissect_ain_TriggerCriteriaFlag },
  {  73, &hf_ain_tSTRCTimer      , BER_CLASS_CON, 156, BER_FLAGS_NOOWNTAG, dissect_ain_TSTRCTimer },
  {  74, &hf_ain_aMAMeasure      , BER_CLASS_CON, 71, BER_FLAGS_NOOWNTAG, dissect_ain_AMAMeasure },
  {  75, &hf_ain_aMAMeasurement  , BER_CLASS_CON, 73, BER_FLAGS_NOOWNTAG, dissect_ain_AMAMeasurement },
  {  76, &hf_ain_clearCauseData  , BER_CLASS_CON, 74, BER_FLAGS_NOOWNTAG, dissect_ain_ClearCauseData },
  {  77, &hf_ain_envelopContent  , BER_CLASS_CON, 75, BER_FLAGS_NOOWNTAG, dissect_ain_EnvelopContent },
  {  78, &hf_ain_iPReturnBlock   , BER_CLASS_CON, 78, BER_FLAGS_NOOWNTAG, dissect_ain_IPReturnBlock },
  {  79, &hf_ain_sap             , BER_CLASS_CON, 81, BER_FLAGS_NOOWNTAG, dissect_ain_Sap },
  {  80, &hf_ain_aMASetHexABIndicator, BER_CLASS_CON, 82, BER_FLAGS_NOOWNTAG, dissect_ain_AMASetHexABIndicator },
  {  81, &hf_ain_serviceContext  , BER_CLASS_CON, 83, BER_FLAGS_NOOWNTAG, dissect_ain_ServiceContext },
  {  82, &hf_ain_extensionParameter, BER_CLASS_CON, 84, BER_FLAGS_IMPLTAG, dissect_ain_ExtensionParameter },
  {  83, &hf_ain_securityEnvelope, BER_CLASS_CON, 85, BER_FLAGS_NOOWNTAG, dissect_ain_SecurityEnvelope },
  {  84, &hf_ain_destinationAddress, BER_CLASS_CON, 86, BER_FLAGS_NOOWNTAG, dissect_ain_DestinationAddress },
  {  85, &hf_ain_derviceProviderID, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_ain_ServiceProviderID },
  {  86, &hf_ain_aMABillingFeature, BER_CLASS_CON, 88, BER_FLAGS_NOOWNTAG, dissect_ain_AMABillingFeature },
  {  87, &hf_ain_aMASequenceNumber, BER_CLASS_CON, 89, BER_FLAGS_NOOWNTAG, dissect_ain_AMASequenceNumber },
  {  88, &hf_ain_applicationIndicator, BER_CLASS_CON, 90, BER_FLAGS_NOOWNTAG, dissect_ain_ApplicationIndicator },
  {  89, &hf_ain_oNoAnswerTimer  , BER_CLASS_CON, 91, BER_FLAGS_NOOWNTAG, dissect_ain_ONoAnswerTimer },
  {  90, &hf_ain_eDPRequest      , BER_CLASS_CON, 92, BER_FLAGS_NOOWNTAG, dissect_ain_EDPRequest },
  {  91, &hf_ain_eDPNotification , BER_CLASS_CON, 93, BER_FLAGS_NOOWNTAG, dissect_ain_EDPNotification },
  {  92, &hf_ain_busyType        , BER_CLASS_CON, 94, BER_FLAGS_NOOWNTAG, dissect_ain_BusyType },
  {  93, &hf_ain_aMABAFModules   , BER_CLASS_CON, 95, BER_FLAGS_NOOWNTAG, dissect_ain_AMABAFModules },
  {  94, &hf_ain_sTRConnection   , BER_CLASS_CON, 96, BER_FLAGS_NOOWNTAG, dissect_ain_STRConnection },
  {  95, &hf_ain_errorCause      , BER_CLASS_CON, 56, BER_FLAGS_NOOWNTAG, dissect_ain_ErrorCause },
  {  96, &hf_ain_resultCause     , BER_CLASS_CON, 151, BER_FLAGS_NOOWNTAG, dissect_ain_ResultCause },
  {  97, &hf_ain_cTRConnection   , BER_CLASS_CON, 141, BER_FLAGS_NOOWNTAG, dissect_ain_CTRConnection },
  {  98, &hf_ain_rTPReroutingNumber, BER_CLASS_CON, 143, BER_FLAGS_NOOWNTAG, dissect_ain_RTPReroutingNumber },
  {  99, &hf_ain_rTPServiceIndicator, BER_CLASS_CON, 144, BER_FLAGS_NOOWNTAG, dissect_ain_RTPServiceIndicator },
  { 100, &hf_ain_administrableObject, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_ain_AdministrableObject },
  { 101, &hf_ain_envelopeEncodingAuthority, BER_CLASS_CON, 98, BER_FLAGS_NOOWNTAG, dissect_ain_EnvelopeEncodingAuthority },
  { 102, &hf_ain_tNoAnswerTimer  , BER_CLASS_CON, 99, BER_FLAGS_NOOWNTAG, dissect_ain_TNoAnswerTimer },
  { 103, &hf_ain_editListType    , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_ain_EditListType },
  { 104, &hf_ain_aCGGlobalOverride, BER_CLASS_CON, 110, BER_FLAGS_NOOWNTAG, dissect_ain_ACGGlobalOverride },
  { 105, &hf_ain_notificationIndicator, BER_CLASS_CON, 111, BER_FLAGS_IMPLTAG, dissect_ain_NotificationIndicator },
  { 106, &hf_ain_aMALineNumber   , BER_CLASS_CON, 9, BER_FLAGS_NOOWNTAG, dissect_ain_AMALineNumber },
  { 107, &hf_ain_aMADigitsDialedWC, BER_CLASS_CON, 8, BER_FLAGS_NOOWNTAG, dissect_ain_AMADigitsDialedWC },
  { 108, &hf_ain_carrierUsage    , BER_CLASS_CON, 79, BER_FLAGS_NOOWNTAG, dissect_ain_CarrierUsage },
  { 109, &hf_ain_closeCause      , BER_CLASS_CON, 72, BER_FLAGS_NOOWNTAG, dissect_ain_CloseCause },
  { 110, &hf_ain_dPConverter     , BER_CLASS_CON, 76, BER_FLAGS_NOOWNTAG, dissect_ain_DPConverter },
  { 111, &hf_ain_failureCauseData, BER_CLASS_CON, 112, BER_FLAGS_NOOWNTAG, dissect_ain_FailureCauseData },
  { 112, &hf_ain_genericAddress  , BER_CLASS_CON, 80, BER_FLAGS_NOOWNTAG, dissect_ain_GenericAddress },
  { 113, &hf_ain_srhrGroupID     , BER_CLASS_CON, 77, BER_FLAGS_NOOWNTAG, dissect_ain_SrhrGroupID },
  { 114, &hf_ain_genericAddressList, BER_CLASS_CON, 107, BER_FLAGS_NOOWNTAG, dissect_ain_GenericAddressList },
  { 115, &hf_ain_networkSpecificFacilities, BER_CLASS_CON, 108, BER_FLAGS_NOOWNTAG, dissect_ain_NetworkSpecificFacilities },
  { 116, &hf_ain_forwardCallIndicator, BER_CLASS_CON, 113, BER_FLAGS_NOOWNTAG, dissect_ain_ForwardCallIndicator },
  { 117, &hf_ain_alternateDialingPlanInd, BER_CLASS_CON, 115, BER_FLAGS_NOOWNTAG, dissect_ain_AlternateDialingPlanInd },
  { 118, &hf_ain_disconnectCause , BER_CLASS_CON, 116, BER_FLAGS_NOOWNTAG, dissect_ain_DisconnectCause },
  { 119, &hf_ain_aMAServiceProviderID, BER_CLASS_CON, 101, BER_FLAGS_NOOWNTAG, dissect_ain_AMAServiceProviderID },
  { 120, &hf_ain_congestionLevel , BER_CLASS_CON, 117, BER_FLAGS_NOOWNTAG, dissect_ain_CongestionLevel },
  { 121, &hf_ain_controlEncountered, BER_CLASS_CON, 127, BER_FLAGS_NOOWNTAG, dissect_ain_ControlEncountered },
  { 122, &hf_ain_infoProvided    , BER_CLASS_CON, 100, BER_FLAGS_NOOWNTAG, dissect_ain_InfoProvided },
  { 123, &hf_ain_provideInfo     , BER_CLASS_CON, 114, BER_FLAGS_NOOWNTAG, dissect_ain_ProvideInfo },
  { 124, &hf_ain_signalingPointCode, BER_CLASS_CON, 142, BER_FLAGS_NOOWNTAG, dissect_ain_SignalingPointCode },
  { 125, &hf_ain_subsystemNumber , BER_CLASS_CON, 130, BER_FLAGS_NOOWNTAG, dissect_ain_SubsystemNumber },
  { 126, &hf_ain_notificationDuration, BER_CLASS_CON, 128, BER_FLAGS_NOOWNTAG, dissect_ain_NotificationDuration },
  { 127, &hf_ain_wakeUpDuration  , BER_CLASS_CON, 131, BER_FLAGS_NOOWNTAG, dissect_ain_WakeUpDuration },
  { 128, &hf_ain_oSIIndicator    , BER_CLASS_CON, 129, BER_FLAGS_NOOWNTAG, dissect_ain_OSIIndicator },
  { 129, &hf_ain_legID           , BER_CLASS_CON, 132, BER_FLAGS_NOOWNTAG, dissect_ain_LegID },
  { 130, &hf_ain_ccID            , BER_CLASS_CON, 133, BER_FLAGS_NOOWNTAG, dissect_ain_CcID },
  { 131, &hf_ain_bCMType         , BER_CLASS_CON, 134, BER_FLAGS_NOOWNTAG, dissect_ain_BCMType },
  { 132, &hf_ain_pointInCall     , BER_CLASS_CON, 135, BER_FLAGS_NOOWNTAG, dissect_ain_PointInCall },
  { 133, &hf_ain_featureActivatorID, BER_CLASS_CON, 136, BER_FLAGS_NOOWNTAG, dissect_ain_FeatureActivatorID },
  { 134, &hf_ain_csID            , BER_CLASS_CON, 137, BER_FLAGS_NOOWNTAG, dissect_ain_CsID },
  { 135, &hf_ain_lampTreatment   , BER_CLASS_CON, 138, BER_FLAGS_NOOWNTAG, dissect_ain_LampTreatment },
  { 136, &hf_ain_timeoutTimer    , BER_CLASS_CON, 139, BER_FLAGS_NOOWNTAG, dissect_ain_TimeoutTimer },
  { 137, &hf_ain_transID         , BER_CLASS_CON, 163, BER_FLAGS_NOOWNTAG, dissect_ain_TransID },
  { 138, &hf_ain_actResult       , BER_CLASS_CON, 164, BER_FLAGS_NOOWNTAG, dissect_ain_ActResult },
  { 139, &hf_ain_extendedRinging , BER_CLASS_CON, 146, BER_FLAGS_NOOWNTAG, dissect_ain_ExtendedRinging },
  { 140, &hf_ain_jurisdictionInformation, BER_CLASS_CON, 147, BER_FLAGS_NOOWNTAG, dissect_ain_JurisdictionInformation },
  { 141, &hf_ain_prefix          , BER_CLASS_CON, 148, BER_FLAGS_NOOWNTAG, dissect_ain_Prefix },
  { 142, &hf_ain_genericDigitsList, BER_CLASS_CON, 150, BER_FLAGS_NOOWNTAG, dissect_ain_GenericDigitsList },
  { 143, &hf_ain_applyRestrictions, BER_CLASS_CON, 152, BER_FLAGS_NOOWNTAG, dissect_ain_ApplyRestrictions },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_Parms(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Parms_choice, hf_index, ett_ain_Parms,
                                 NULL);

  return offset;
}


static const ber_sequence_t InvParms_sequence_of[1] = {
  { &hf_ain_InvParms_item   , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ain_Parms },
};

static int
dissect_ain_InvParms(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      InvParms_sequence_of, hf_index, ett_ain_InvParms);

  return offset;
}


static const ber_sequence_t FailedMessage_U_sequence[] = {
  { &hf_ain_opCode          , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_ain_INTEGER },
  { &hf_ain_parameter       , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_OCTET_STRING },
  { &hf_ain_invParms        , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ain_InvParms },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_FailedMessage_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   FailedMessage_U_sequence, hf_index, ett_ain_FailedMessage_U);

  return offset;
}



static int
dissect_ain_FailedMessage(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 57, true, dissect_ain_FailedMessage_U);

  return offset;
}


static const ber_sequence_t ApplicationErrorString_U_sequence[] = {
  { &hf_ain_errorCause      , BER_CLASS_CON, 56, BER_FLAGS_NOOWNTAG, dissect_ain_ErrorCause },
  { &hf_ain_failedMessage   , BER_CLASS_CON, 57, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_FailedMessage },
  { &hf_ain_userID          , BER_CLASS_CON, 53, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_UserID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_ApplicationErrorString_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ApplicationErrorString_U_sequence, hf_index, ett_ain_ApplicationErrorString_U);

  return offset;
}



static int
dissect_ain_ApplicationErrorString(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 55, true, dissect_ain_ApplicationErrorString_U);

  return offset;
}


static const ber_sequence_t PAR_applicationError_sequence[] = {
  { &hf_ain_applicationErrorString, BER_CLASS_CON, 55, BER_FLAGS_NOOWNTAG, dissect_ain_ApplicationErrorString },
  { &hf_ain_extensionParameter, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ExtensionParameter },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_PAR_applicationError(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PAR_applicationError_sequence, hf_index, ett_ain_PAR_applicationError);

  return offset;
}


static const ber_sequence_t PAR_failureReport_sequence[] = {
  { &hf_ain_failureCause    , BER_CLASS_CON, 32, BER_FLAGS_NOOWNTAG, dissect_ain_FailureCause },
  { &hf_ain_failureCauseData, BER_CLASS_CON, 112, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_FailureCauseData },
  { &hf_ain_extensionParameter, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_ExtensionParameter },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_PAR_failureReport(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PAR_failureReport_sequence, hf_index, ett_ain_PAR_failureReport);

  return offset;
}



static int
dissect_ain_T_local(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &opcode);

    if (ain_opcode_type == AIN_OPCODE_RETURN_ERROR){
      errorCode = opcode;
      col_append_str(actx->pinfo->cinfo, COL_INFO, val_to_str(errorCode, ain_err_code_string_vals, "Unknown AIN error (%u)"));
      col_append_str(actx->pinfo->cinfo, COL_INFO, " ");
      col_set_fence(actx->pinfo->cinfo, COL_INFO);
    }else{
      col_append_str(actx->pinfo->cinfo, COL_INFO, val_to_str(opcode, ain_opr_code_strings, "Unknown AIN (%u)"));
      col_append_str(actx->pinfo->cinfo, COL_INFO, " ");
      col_set_fence(actx->pinfo->cinfo, COL_INFO);
    }


  return offset;
}


static const value_string ain_Code_vals[] = {
  {   0, "local" },
  {   1, "global" },
  { 0, NULL }
};

static const ber_choice_t Code_choice[] = {
  {   0, &hf_ain_local           , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_ain_T_local },
  {   1, &hf_ain_global          , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_ain_OBJECT_IDENTIFIER },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_Code(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Code_choice, hf_index, ett_ain_Code,
                                 NULL);

  return offset;
}


static const value_string ain_InvokeId_vals[] = {
  {   0, "present" },
  {   1, "absent" },
  { 0, NULL }
};

static const ber_choice_t InvokeId_choice[] = {
  {   0, &hf_ain_present_01      , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_ain_INTEGER },
  {   1, &hf_ain_absent          , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_ain_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_InvokeId(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 InvokeId_choice, hf_index, ett_ain_InvokeId,
                                 NULL);

  return offset;
}



static int
dissect_ain_InvokeId_present(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_ain_T_present(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ain_InvokeId_present(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string ain_T_linkedId_vals[] = {
  {   0, "present" },
  {   1, "absent" },
  { 0, NULL }
};

static const ber_choice_t T_linkedId_choice[] = {
  {   0, &hf_ain_present         , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ain_T_present },
  {   1, &hf_ain_absent          , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ain_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_T_linkedId(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_linkedId_choice, hf_index, ett_ain_T_linkedId,
                                 NULL);

  return offset;
}



static int
dissect_ain_T_argument(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

  offset = dissect_invokeData(tree, tvb, offset, actx);


  return offset;
}


static const ber_sequence_t Invoke_sequence[] = {
  { &hf_ain_invokeId        , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ain_InvokeId },
  { &hf_ain_linkedId        , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ain_T_linkedId },
  { &hf_ain_opcode          , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ain_Code },
  { &hf_ain_argument        , BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_T_argument },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_Invoke(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

  ain_opcode_type=AIN_OPCODE_INVOKE;

  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Invoke_sequence, hf_index, ett_ain_Invoke);

  return offset;
}



static int
dissect_ain_T_result_01(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

  offset = dissect_returnResultData(tree, tvb, offset, actx);


  return offset;
}


static const ber_sequence_t T_result_sequence[] = {
  { &hf_ain_opcode          , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ain_Code },
  { &hf_ain_result_01       , BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_ain_T_result_01 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_T_result(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_result_sequence, hf_index, ett_ain_T_result);

  return offset;
}


static const ber_sequence_t ReturnResult_sequence[] = {
  { &hf_ain_invokeId        , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ain_InvokeId },
  { &hf_ain_result          , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_T_result },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_ReturnResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

  ain_opcode_type=AIN_OPCODE_RETURN_RESULT;

  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ReturnResult_sequence, hf_index, ett_ain_ReturnResult);

  return offset;
}



static int
dissect_ain_T_parameter(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

  offset = dissect_returnErrorData(tree, tvb, offset, actx);


  return offset;
}


static const ber_sequence_t ReturnError_sequence[] = {
  { &hf_ain_invokeId        , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ain_InvokeId },
  { &hf_ain_errcode         , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ain_Code },
  { &hf_ain_parameter_01    , BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ain_T_parameter },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_ReturnError(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

  ain_opcode_type=AIN_OPCODE_RETURN_ERROR;

  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ReturnError_sequence, hf_index, ett_ain_ReturnError);

  return offset;
}


static const value_string ain_GeneralProblem_vals[] = {
  {   0, "unrecognizedPDU" },
  {   1, "mistypedPDU" },
  {   2, "badlyStructuredPDU" },
  { 0, NULL }
};


static int
dissect_ain_GeneralProblem(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string ain_InvokeProblem_vals[] = {
  {   0, "duplicateInvocation" },
  {   1, "unrecognizedOperation" },
  {   2, "mistypedArgument" },
  {   3, "resourceLimitation" },
  {   4, "releaseInProgress" },
  {   5, "unrecognizedLinkedId" },
  {   6, "linkedResponseUnexpected" },
  {   7, "unexpectedLinkedOperation" },
  { 0, NULL }
};


static int
dissect_ain_InvokeProblem(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string ain_ReturnResultProblem_vals[] = {
  {   0, "unrecognizedInvocation" },
  {   1, "resultResponseUnexpected" },
  {   2, "mistypedResult" },
  { 0, NULL }
};


static int
dissect_ain_ReturnResultProblem(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string ain_ReturnErrorProblem_vals[] = {
  {   0, "unrecognizedInvocation" },
  {   1, "errorResponseUnexpected" },
  {   2, "unrecognizedError" },
  {   3, "unexpectedError" },
  {   4, "mistypedParameter" },
  { 0, NULL }
};


static int
dissect_ain_ReturnErrorProblem(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string ain_T_problem_vals[] = {
  {   0, "general" },
  {   1, "invoke" },
  {   2, "returnResult" },
  {   3, "returnError" },
  { 0, NULL }
};

static const ber_choice_t T_problem_choice[] = {
  {   0, &hf_ain_general         , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ain_GeneralProblem },
  {   1, &hf_ain_invokeproblem   , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ain_InvokeProblem },
  {   2, &hf_ain_returnResult_01 , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_ain_ReturnResultProblem },
  {   3, &hf_ain_returnError_01  , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_ain_ReturnErrorProblem },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_T_problem(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_problem_choice, hf_index, ett_ain_T_problem,
                                 NULL);

  return offset;
}


static const ber_sequence_t Reject_sequence[] = {
  { &hf_ain_invokeId        , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ain_InvokeId },
  { &hf_ain_problem         , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ain_T_problem },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_Reject(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

  ain_opcode_type=AIN_OPCODE_REJECT;

  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Reject_sequence, hf_index, ett_ain_Reject);

  return offset;
}


static const ber_choice_t ROS_choice[] = {
  {   1, &hf_ain_invoke          , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ain_Invoke },
  {   2, &hf_ain_returnResult    , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_ain_ReturnResult },
  {   3, &hf_ain_returnError     , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_ain_ReturnError },
  {   4, &hf_ain_reject          , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_ain_Reject },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ain_ROS(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ROS_choice, hf_index, ett_ain_ROS,
                                 NULL);

  return offset;
}

/*--- PDUs ---*/

static int dissect_CallInfoFromResourceArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ain_CallInfoFromResourceArg(false, tvb, offset, &asn1_ctx, tree, hf_ain_CallInfoFromResourceArg_PDU);
  return offset;
}
static int dissect_CloseArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ain_CloseArg(false, tvb, offset, &asn1_ctx, tree, hf_ain_CloseArg_PDU);
  return offset;
}
static int dissect_CTRClearArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ain_CTRClearArg(false, tvb, offset, &asn1_ctx, tree, hf_ain_CTRClearArg_PDU);
  return offset;
}
static int dissect_FailureOutcomeArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ain_FailureOutcomeArg(false, tvb, offset, &asn1_ctx, tree, hf_ain_FailureOutcomeArg_PDU);
  return offset;
}
static int dissect_InfoAnalyzedArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ain_InfoAnalyzedArg(false, tvb, offset, &asn1_ctx, tree, hf_ain_InfoAnalyzedArg_PDU);
  return offset;
}
static int dissect_InfoCollectedArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ain_InfoCollectedArg(false, tvb, offset, &asn1_ctx, tree, hf_ain_InfoCollectedArg_PDU);
  return offset;
}
static int dissect_NetworkBusyArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ain_NetworkBusyArg(false, tvb, offset, &asn1_ctx, tree, hf_ain_NetworkBusyArg_PDU);
  return offset;
}
static int dissect_OAnswerArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ain_OAnswerArg(false, tvb, offset, &asn1_ctx, tree, hf_ain_OAnswerArg_PDU);
  return offset;
}
static int dissect_OAbandonArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ain_OAbandonArg(false, tvb, offset, &asn1_ctx, tree, hf_ain_OAbandonArg_PDU);
  return offset;
}
static int dissect_ODisconnectArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ain_ODisconnectArg(false, tvb, offset, &asn1_ctx, tree, hf_ain_ODisconnectArg_PDU);
  return offset;
}
static int dissect_OMidCallArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ain_OMidCallArg(false, tvb, offset, &asn1_ctx, tree, hf_ain_OMidCallArg_PDU);
  return offset;
}
static int dissect_ONoAnswerArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ain_ONoAnswerArg(false, tvb, offset, &asn1_ctx, tree, hf_ain_ONoAnswerArg_PDU);
  return offset;
}
static int dissect_OSuspendedArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ain_OSuspendedArg(false, tvb, offset, &asn1_ctx, tree, hf_ain_OSuspendedArg_PDU);
  return offset;
}
static int dissect_OTermSeizedArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ain_OTermSeizedArg(false, tvb, offset, &asn1_ctx, tree, hf_ain_OTermSeizedArg_PDU);
  return offset;
}
static int dissect_OriginationAttemptArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ain_OriginationAttemptArg(false, tvb, offset, &asn1_ctx, tree, hf_ain_OriginationAttemptArg_PDU);
  return offset;
}
static int dissect_ResourceClearArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ain_ResourceClearArg(false, tvb, offset, &asn1_ctx, tree, hf_ain_ResourceClearArg_PDU);
  return offset;
}
static int dissect_RES_resourceClear_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ain_RES_resourceClear(false, tvb, offset, &asn1_ctx, tree, hf_ain_RES_resourceClear_PDU);
  return offset;
}
static int dissect_SuccessOutcomeArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ain_SuccessOutcomeArg(false, tvb, offset, &asn1_ctx, tree, hf_ain_SuccessOutcomeArg_PDU);
  return offset;
}
static int dissect_TAnswerArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ain_TAnswerArg(false, tvb, offset, &asn1_ctx, tree, hf_ain_TAnswerArg_PDU);
  return offset;
}
static int dissect_TBusyArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ain_TBusyArg(false, tvb, offset, &asn1_ctx, tree, hf_ain_TBusyArg_PDU);
  return offset;
}
static int dissect_TDisconnectArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ain_TDisconnectArg(false, tvb, offset, &asn1_ctx, tree, hf_ain_TDisconnectArg_PDU);
  return offset;
}
static int dissect_TDTMFEnteredArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ain_TDTMFEnteredArg(false, tvb, offset, &asn1_ctx, tree, hf_ain_TDTMFEnteredArg_PDU);
  return offset;
}
static int dissect_TMidCallArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ain_TMidCallArg(false, tvb, offset, &asn1_ctx, tree, hf_ain_TMidCallArg_PDU);
  return offset;
}
static int dissect_TNoAnswerArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ain_TNoAnswerArg(false, tvb, offset, &asn1_ctx, tree, hf_ain_TNoAnswerArg_PDU);
  return offset;
}
static int dissect_TerminationAttemptArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ain_TerminationAttemptArg(false, tvb, offset, &asn1_ctx, tree, hf_ain_TerminationAttemptArg_PDU);
  return offset;
}
static int dissect_TermResourceAvailableArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ain_TermResourceAvailableArg(false, tvb, offset, &asn1_ctx, tree, hf_ain_TermResourceAvailableArg_PDU);
  return offset;
}
static int dissect_TimeoutArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ain_TimeoutArg(false, tvb, offset, &asn1_ctx, tree, hf_ain_TimeoutArg_PDU);
  return offset;
}
static int dissect_AnalyzeRouteArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ain_AnalyzeRouteArg(false, tvb, offset, &asn1_ctx, tree, hf_ain_AnalyzeRouteArg_PDU);
  return offset;
}
static int dissect_AuthorizeTerminationArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ain_AuthorizeTerminationArg(false, tvb, offset, &asn1_ctx, tree, hf_ain_AuthorizeTerminationArg_PDU);
  return offset;
}
static int dissect_CancelResourceEventArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ain_CancelResourceEventArg(false, tvb, offset, &asn1_ctx, tree, hf_ain_CancelResourceEventArg_PDU);
  return offset;
}
static int dissect_CollectInformationArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ain_CollectInformationArg(false, tvb, offset, &asn1_ctx, tree, hf_ain_CollectInformationArg_PDU);
  return offset;
}
static int dissect_ConnectToResourceArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ain_ConnectToResourceArg(false, tvb, offset, &asn1_ctx, tree, hf_ain_ConnectToResourceArg_PDU);
  return offset;
}
static int dissect_ContinueArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ain_ContinueArg(false, tvb, offset, &asn1_ctx, tree, hf_ain_ContinueArg_PDU);
  return offset;
}
static int dissect_CreateCallArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ain_CreateCallArg(false, tvb, offset, &asn1_ctx, tree, hf_ain_CreateCallArg_PDU);
  return offset;
}
static int dissect_CreateCallRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ain_CreateCallRes(false, tvb, offset, &asn1_ctx, tree, hf_ain_CreateCallRes_PDU);
  return offset;
}
static int dissect_DisconnectArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ain_DisconnectArg(false, tvb, offset, &asn1_ctx, tree, hf_ain_DisconnectArg_PDU);
  return offset;
}
static int dissect_DisconnectLegArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ain_DisconnectLegArg(false, tvb, offset, &asn1_ctx, tree, hf_ain_DisconnectLegArg_PDU);
  return offset;
}
static int dissect_ForwardCallArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ain_ForwardCallArg(false, tvb, offset, &asn1_ctx, tree, hf_ain_ForwardCallArg_PDU);
  return offset;
}
static int dissect_MergeCallArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ain_MergeCallArg(false, tvb, offset, &asn1_ctx, tree, hf_ain_MergeCallArg_PDU);
  return offset;
}
static int dissect_MoveLegArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ain_MoveLegArg(false, tvb, offset, &asn1_ctx, tree, hf_ain_MoveLegArg_PDU);
  return offset;
}
static int dissect_OfferCallArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ain_OfferCallArg(false, tvb, offset, &asn1_ctx, tree, hf_ain_OfferCallArg_PDU);
  return offset;
}
static int dissect_OriginateCallArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ain_OriginateCallArg(false, tvb, offset, &asn1_ctx, tree, hf_ain_OriginateCallArg_PDU);
  return offset;
}
static int dissect_ReconnectArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ain_ReconnectArg(false, tvb, offset, &asn1_ctx, tree, hf_ain_ReconnectArg_PDU);
  return offset;
}
static int dissect_SendToResourceArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ain_SendToResourceArg(false, tvb, offset, &asn1_ctx, tree, hf_ain_SendToResourceArg_PDU);
  return offset;
}
static int dissect_RES_sendToResource_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ain_RES_sendToResource(false, tvb, offset, &asn1_ctx, tree, hf_ain_RES_sendToResource_PDU);
  return offset;
}
static int dissect_SetTimerArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ain_SetTimerArg(false, tvb, offset, &asn1_ctx, tree, hf_ain_SetTimerArg_PDU);
  return offset;
}
static int dissect_TimerUpdated_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ain_TimerUpdated(false, tvb, offset, &asn1_ctx, tree, hf_ain_TimerUpdated_PDU);
  return offset;
}
static int dissect_SplitLegArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ain_SplitLegArg(false, tvb, offset, &asn1_ctx, tree, hf_ain_SplitLegArg_PDU);
  return offset;
}
static int dissect_AcgArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ain_AcgArg(false, tvb, offset, &asn1_ctx, tree, hf_ain_AcgArg_PDU);
  return offset;
}
static int dissect_AcgGlobalCtrlRestoreArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ain_AcgGlobalCtrlRestoreArg(false, tvb, offset, &asn1_ctx, tree, hf_ain_AcgGlobalCtrlRestoreArg_PDU);
  return offset;
}
static int dissect_RES_acgGlobalCtrlRestore_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ain_RES_acgGlobalCtrlRestore(false, tvb, offset, &asn1_ctx, tree, hf_ain_RES_acgGlobalCtrlRestore_PDU);
  return offset;
}
static int dissect_AcgOverflowArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ain_AcgOverflowArg(false, tvb, offset, &asn1_ctx, tree, hf_ain_AcgOverflowArg_PDU);
  return offset;
}
static int dissect_ActivityTestArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ain_ActivityTestArg(false, tvb, offset, &asn1_ctx, tree, hf_ain_ActivityTestArg_PDU);
  return offset;
}
static int dissect_RES_activityTest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ain_RES_activityTest(false, tvb, offset, &asn1_ctx, tree, hf_ain_RES_activityTest_PDU);
  return offset;
}
static int dissect_CallTypeRequestArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ain_CallTypeRequestArg(false, tvb, offset, &asn1_ctx, tree, hf_ain_CallTypeRequestArg_PDU);
  return offset;
}
static int dissect_RES_callTypeRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ain_RES_callTypeRequest(false, tvb, offset, &asn1_ctx, tree, hf_ain_RES_callTypeRequest_PDU);
  return offset;
}
static int dissect_ControlRequestArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ain_ControlRequestArg(false, tvb, offset, &asn1_ctx, tree, hf_ain_ControlRequestArg_PDU);
  return offset;
}
static int dissect_EchoRequestArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ain_EchoRequestArg(false, tvb, offset, &asn1_ctx, tree, hf_ain_EchoRequestArg_PDU);
  return offset;
}
static int dissect_RES_echoRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ain_RES_echoRequest(false, tvb, offset, &asn1_ctx, tree, hf_ain_RES_echoRequest_PDU);
  return offset;
}
static int dissect_FurnishAMAInformationArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ain_FurnishAMAInformationArg(false, tvb, offset, &asn1_ctx, tree, hf_ain_FurnishAMAInformationArg_PDU);
  return offset;
}
static int dissect_MonitorForChangeArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ain_MonitorForChangeArg(false, tvb, offset, &asn1_ctx, tree, hf_ain_MonitorForChangeArg_PDU);
  return offset;
}
static int dissect_MonitorSuccessArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ain_MonitorSuccessArg(false, tvb, offset, &asn1_ctx, tree, hf_ain_MonitorSuccessArg_PDU);
  return offset;
}
static int dissect_NCADataArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ain_NCADataArg(false, tvb, offset, &asn1_ctx, tree, hf_ain_NCADataArg_PDU);
  return offset;
}
static int dissect_NCARequestArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ain_NCARequestArg(false, tvb, offset, &asn1_ctx, tree, hf_ain_NCARequestArg_PDU);
  return offset;
}
static int dissect_RES_nCARequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ain_RES_nCARequest(false, tvb, offset, &asn1_ctx, tree, hf_ain_RES_nCARequest_PDU);
  return offset;
}
static int dissect_QueryRequestArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ain_QueryRequestArg(false, tvb, offset, &asn1_ctx, tree, hf_ain_QueryRequestArg_PDU);
  return offset;
}
static int dissect_RES_queryRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ain_RES_queryRequest(false, tvb, offset, &asn1_ctx, tree, hf_ain_RES_queryRequest_PDU);
  return offset;
}
static int dissect_RequestReportBCMEventArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ain_RequestReportBCMEventArg(false, tvb, offset, &asn1_ctx, tree, hf_ain_RequestReportBCMEventArg_PDU);
  return offset;
}
static int dissect_StatusReportedArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ain_StatusReportedArg(false, tvb, offset, &asn1_ctx, tree, hf_ain_StatusReportedArg_PDU);
  return offset;
}
static int dissect_TerminationNotificationArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ain_TerminationNotificationArg(false, tvb, offset, &asn1_ctx, tree, hf_ain_TerminationNotificationArg_PDU);
  return offset;
}
static int dissect_UpdateArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ain_UpdateArg(false, tvb, offset, &asn1_ctx, tree, hf_ain_UpdateArg_PDU);
  return offset;
}
static int dissect_RES_update_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ain_RES_update(false, tvb, offset, &asn1_ctx, tree, hf_ain_RES_update_PDU);
  return offset;
}
static int dissect_UpdateRequestArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ain_UpdateRequestArg(false, tvb, offset, &asn1_ctx, tree, hf_ain_UpdateRequestArg_PDU);
  return offset;
}
static int dissect_RES_updateRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ain_RES_updateRequest(false, tvb, offset, &asn1_ctx, tree, hf_ain_RES_updateRequest_PDU);
  return offset;
}
static int dissect_PAR_applicationError_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ain_PAR_applicationError(false, tvb, offset, &asn1_ctx, tree, hf_ain_PAR_applicationError_PDU);
  return offset;
}
static int dissect_PAR_failureReport_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ain_PAR_failureReport(false, tvb, offset, &asn1_ctx, tree, hf_ain_PAR_failureReport_PDU);
  return offset;
}



static int dissect_invokeData(proto_tree *tree, tvbuff_t *tvb, int offset, asn1_ctx_t *actx) {

  switch(opcode){
    case 26116:  /* callInfoFromResource */
      offset= dissect_CallInfoFromResourceArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case 28161:  /* close */
      offset= dissect_CloseArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case 26118:  /* cTRClear */
      offset= dissect_CTRClearArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case 25604:  /* failureOutcome */
      offset= dissect_FailureOutcomeArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case 25603:  /* infoAnalyzed */
      offset= dissect_InfoAnalyzedArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case 25602:  /* infoCollected */
      offset= dissect_InfoCollectedArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case 25623:  /* networkBusy */
      offset= dissect_NetworkBusyArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case 25611:  /* oAnswer */
      offset= dissect_OAnswerArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case 25614:  /* oAbandon */
      offset= dissect_OAbandonArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case 25626:  /* oDisconnect */
      offset= dissect_ODisconnectArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case 25615:  /* oMidCall */
      offset= dissect_OMidCallArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case 25609:  /* oNoAnswer */
      offset= dissect_ONoAnswerArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case 25625:  /* oSuspended */
      offset= dissect_OSuspendedArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case 25612:  /* oTermSeized */
      offset= dissect_OTermSeizedArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case 25624:  /* originationAttempt */
      offset= dissect_OriginationAttemptArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case 26114:  /* resourceClear */
      offset= dissect_ResourceClearArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case 25617:  /* successOutcome */
      offset= dissect_SuccessOutcomeArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case 25610:  /* tAnswer */
      offset= dissect_TAnswerArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case 25606:  /* tBusy */
      offset= dissect_TBusyArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case 25618:  /* tDisconnect */
      offset= dissect_TDisconnectArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case 25628:  /* tDTMFEntered */
      offset= dissect_TDTMFEnteredArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case 25619:  /* tMidCall */
      offset= dissect_TMidCallArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case 25608:  /* tNoAnswer */
      offset= dissect_TNoAnswerArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case 25605:  /* terminationAttempt */
      offset= dissect_TerminationAttemptArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case 25613:  /* termResourceAvailable */
      offset= dissect_TermResourceAvailableArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case 25620:  /* timeout */
      offset= dissect_TimeoutArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case 25857:  /* analyzeRoute */
      offset= dissect_AnalyzeRouteArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case 25858:  /* authorizeTermination */
      offset= dissect_AuthorizeTerminationArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case 26115:  /* cancelResourceEvent */
      offset= dissect_CancelResourceEventArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case 25861:  /* collectInformation */
      offset= dissect_CollectInformationArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case 26117:  /* connectToResource */
      offset= dissect_ConnectToResourceArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case 25869:  /* continue */
      offset= dissect_ContinueArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case 25863:  /* createCall */
      offset= dissect_CreateCallArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case 25859:  /* disconnect */
      offset= dissect_DisconnectArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case 25864:  /* disconnectLeg */
      offset= dissect_DisconnectLegArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case 27137:  /* forwardCall */
      offset= dissect_ForwardCallArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case 25865:  /* mergeCall */
      offset= dissect_MergeCallArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case 25866:  /* moveLeg */
      offset= dissect_MoveLegArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case 25860:  /* offerCall */
      offset= dissect_OfferCallArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case 25867:  /* originateCall */
      offset= dissect_OriginateCallArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case 25870:  /* reconnect */
      offset= dissect_ReconnectArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case 26113:  /* sendToResource */
      offset= dissect_SendToResourceArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case 26889:  /* setTimer */
      offset= dissect_SetTimerArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case 25868:  /* splitLeg */
      offset= dissect_SplitLegArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case 26881:  /* acg */
      offset= dissect_AcgArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case 26883:  /* acgGlobalCtrlRestore */
      offset= dissect_AcgGlobalCtrlRestoreArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case 26884:  /* acgOverflow */
      offset= dissect_AcgOverflowArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case 26886:  /* activityTest */
      offset= dissect_ActivityTestArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case 26887:  /* callTypeRequest */
      offset= dissect_CallTypeRequestArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case 26885:  /* controlRequest */
      offset= dissect_ControlRequestArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case 26882:  /* echoRequest */
      offset= dissect_EchoRequestArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case 27649:  /* furnishAMAInformation */
      offset= dissect_FurnishAMAInformationArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case 26369:  /* monitorForChange */
      offset= dissect_MonitorForChangeArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case 26371:  /* monitorSuccess */
      offset= dissect_MonitorSuccessArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case 27394:  /* nCAData */
      offset= dissect_NCADataArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case 27393:  /* nCARequest */
      offset= dissect_NCARequestArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case 26626:  /* queryRequest */
      offset= dissect_QueryRequestArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case 27905:  /* requestReportBCMEvent */
      offset= dissect_RequestReportBCMEventArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case 26370:  /* statusReported */
      offset= dissect_StatusReportedArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case 26372:  /* terminationNotification */
      offset= dissect_TerminationNotificationArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case 26627:  /* update */
      offset= dissect_UpdateArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case 26625:  /* updateRequest */
      offset= dissect_UpdateRequestArg_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    default:
      proto_tree_add_expert_format(tree, actx->pinfo, &ei_ain_unknown_invokeData,
                                   tvb, offset, -1, "Unknown invokeData %d", opcode);
      /* todo call the asn.1 dissector */
      break;
  }
  return offset;
}


static int dissect_returnResultData(proto_tree *tree, tvbuff_t *tvb, int offset,asn1_ctx_t *actx) {
  switch(opcode){
    case 26114:  /* resourceClear */
      offset= dissect_RES_resourceClear_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case 25863:  /* createCall */
      offset= dissect_CreateCallRes_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case 26113:  /* sendToResource */
      offset= dissect_RES_sendToResource_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case 26889:  /* setTimer */
      offset= dissect_TimerUpdated_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case 26883:  /* acgGlobalCtrlRestore */
      offset= dissect_RES_acgGlobalCtrlRestore_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case 26886:  /* activityTest */
      offset= dissect_RES_activityTest_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case 26887:  /* callTypeRequest */
      offset= dissect_RES_callTypeRequest_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case 26882:  /* echoRequest */
      offset= dissect_RES_echoRequest_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case 27393:  /* nCARequest */
      offset= dissect_RES_nCARequest_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case 26626:  /* queryRequest */
      offset= dissect_RES_queryRequest_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case 26627:  /* update */
      offset= dissect_RES_update_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case 26625:  /* updateRequest */
      offset= dissect_RES_updateRequest_PDU(tvb, actx->pinfo , tree , NULL);
      break;
  default:
    proto_tree_add_expert_format(tree, actx->pinfo, &ei_ain_unknown_returnResultData,
                                 tvb, offset, -1, "Unknown returnResultData %d", opcode);
  }
  return offset;
}


static int dissect_returnErrorData(proto_tree *tree, tvbuff_t *tvb, int offset,asn1_ctx_t *actx) {
  switch(errorCode) {
    case 1:  /* applicationError */
      offset= dissect_PAR_applicationError_PDU(tvb, actx->pinfo , tree , NULL);
      break;
    case 2:  /* failureReport */
      offset= dissect_PAR_failureReport_PDU(tvb, actx->pinfo , tree , NULL);
      break;
  default:
    proto_tree_add_expert_format(tree, actx->pinfo, &ei_ain_unknown_returnErrorData,
                                 tvb, offset, -1, "Unknown returnErrorData %d", opcode);
  }
  return offset;
}



static int
dissect_ain(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data _U_)
{
    proto_item *ain_item;
    proto_tree *ain_tree = NULL;
    struct ansi_tcap_private_t *p_private_tcap = (struct ansi_tcap_private_t *)data;
    asn1_ctx_t asn1_ctx;
    asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);

    /* The TCAP dissector should have provided data but didn't so reject it. */
    if (data == NULL)
        return 0;
    /*
    * Make entry in the Protocol column on summary display
    */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "AIN");

    /*
    * create the AIN protocol tree
    */
    ain_item = proto_tree_add_item(parent_tree, proto_ain, tvb, 0, -1, ENC_NA);
    ain_tree = proto_item_add_subtree(ain_item, ett_ain);

    switch (p_private_tcap->d.pdu) {
        /*
        1 : invoke,
        2 : returnResult,
        3 : returnError,
        4 : reject
        */
    case 1:
        opcode = p_private_tcap->d.OperationCode_private;
        /*ansi_map_is_invoke = true;*/
        col_add_fstr(pinfo->cinfo, COL_INFO, "%s Invoke ", val_to_str(opcode, ain_opr_code_strings, "Unknown AIN PDU (%u)"));
        proto_item_append_text(p_private_tcap->d.OperationCode_item, " %s", val_to_str(opcode, ain_opr_code_strings, "Unknown AIN PDU (%u)"));
        dissect_invokeData(ain_tree, tvb, 0, &asn1_ctx);
        /*update_saved_invokedata(pinfo, p_private_tcap);*/
        break;
    //case 2:
    //    opcode = find_saved_invokedata(&asn1_ctx, p_private_tcap);
    //    col_add_fstr(pinfo->cinfo, COL_INFO, "%s ReturnResult ", val_to_str_ext(opcode, &ansi_map_opr_code_strings_ext, "Unknown ANSI-MAP PDU (%u)"));
    //    proto_item_append_text(p_private_tcap->d.OperationCode_item, " %s", val_to_str_ext(opcode, &ansi_map_opr_code_strings_ext, "Unknown ANSI-MAP PDU (%u)"));
    //    dissect_returnData(ain_tree, tvb, 0, &asn1_ctx);
    //    break;
    case 3:
        col_add_fstr(pinfo->cinfo, COL_INFO, "%s ReturnError ", val_to_str(opcode, ain_opr_code_strings, "Unknown AIN PDU (%u)"));
        break;
    case 4:
        col_add_fstr(pinfo->cinfo, COL_INFO, "%s Reject ", val_to_str(opcode, ain_opr_code_strings, "Unknown AIN PDU (%u)"));
        break;
    default:
        /* Must be Invoke ReturnResult ReturnError or Reject */
        DISSECTOR_ASSERT_NOT_REACHED();
        break;
    }

    return tvb_captured_length(tvb);
}

void proto_reg_handoff_ain(void) {

    /*static bool ain_prefs_initialized = false;*/
    /*static range_t *ssn_range;*/

}


void proto_register_ain(void) {
    /* List of fields */

    static hf_register_info hf[] = {


    { &hf_ain_ext_type_oid,
    { "AssignmentAuthority", "ain.ext_type_oid",
    FT_STRING, BASE_NONE, NULL, 0,
    "Type of ExtensionParameter", HFILL } },
    { &hf_ain_odd_even_indicator,
    { "Odd/even indicator",  "ain.odd_even_indicator",
    FT_BOOLEAN, 8, TFS(&tfs_odd_even), 0x80,
    NULL, HFILL } },
    { &hf_ain_nature_of_address,
    { "Nature of address",  "ain.nature_of_address",
    FT_UINT8, BASE_DEC, NULL, 0x7f,
    NULL, HFILL } },
    { &hf_ain_numbering_plan,
    { "Numbering plan",  "ain.numbering_plan",
    FT_UINT8, BASE_DEC, VALS(ain_np_vals), 0x70,
    NULL, HFILL } },
    { &hf_ain_bcd_digits,
    { "BCD digits", "ain.bcd_digits",
    FT_STRING, BASE_NONE, NULL, 0,
    NULL, HFILL } },
    { &hf_ain_carrier_selection,
    { "Carrier Selection",  "ain.carrier_selection",
    FT_UINT8, BASE_DEC, VALS(ain_carrier_selection_vals), 0x0,
    NULL, HFILL } },
    { &hf_ain_nature_of_carrier,
    { "Nature of Carrier",  "ain.nature_of_carrier",
    FT_UINT8, BASE_DEC, VALS(ain_nature_of_carrier_vals), 0xf0,
    NULL, HFILL } },
    { &hf_ain_nr_digits,
    { "Number of Digits",  "ain.nature_of_carrier",
    FT_UINT8, BASE_DEC, NULL, 0x0f,
    NULL, HFILL } },
    { &hf_ain_carrier_bcd_digits,
    { "Carrier digits", "ain.carrier_bcd_digits",
    FT_STRING, BASE_NONE, NULL, 0,
    NULL, HFILL } },
    { &hf_ain_amaslpid,
    { "AMAslpID", "ain.amaslpid",
    FT_STRING, BASE_NONE, NULL, 0,
    NULL, HFILL } },

    { &hf_ain_CallInfoFromResourceArg_PDU,
      { "CallInfoFromResourceArg", "ain.CallInfoFromResourceArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_CloseArg_PDU,
      { "CloseArg", "ain.CloseArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_CTRClearArg_PDU,
      { "CTRClearArg", "ain.CTRClearArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_FailureOutcomeArg_PDU,
      { "FailureOutcomeArg", "ain.FailureOutcomeArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_InfoAnalyzedArg_PDU,
      { "InfoAnalyzedArg", "ain.InfoAnalyzedArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_InfoCollectedArg_PDU,
      { "InfoCollectedArg", "ain.InfoCollectedArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_NetworkBusyArg_PDU,
      { "NetworkBusyArg", "ain.NetworkBusyArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_OAnswerArg_PDU,
      { "OAnswerArg", "ain.OAnswerArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_OAbandonArg_PDU,
      { "OAbandonArg", "ain.OAbandonArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_ODisconnectArg_PDU,
      { "ODisconnectArg", "ain.ODisconnectArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_OMidCallArg_PDU,
      { "OMidCallArg", "ain.OMidCallArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_ONoAnswerArg_PDU,
      { "ONoAnswerArg", "ain.ONoAnswerArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_OSuspendedArg_PDU,
      { "OSuspendedArg", "ain.OSuspendedArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_OTermSeizedArg_PDU,
      { "OTermSeizedArg", "ain.OTermSeizedArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_OriginationAttemptArg_PDU,
      { "OriginationAttemptArg", "ain.OriginationAttemptArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_ResourceClearArg_PDU,
      { "ResourceClearArg", "ain.ResourceClearArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_RES_resourceClear_PDU,
      { "RES-resourceClear", "ain.RES_resourceClear_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_SuccessOutcomeArg_PDU,
      { "SuccessOutcomeArg", "ain.SuccessOutcomeArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_TAnswerArg_PDU,
      { "TAnswerArg", "ain.TAnswerArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_TBusyArg_PDU,
      { "TBusyArg", "ain.TBusyArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_TDisconnectArg_PDU,
      { "TDisconnectArg", "ain.TDisconnectArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_TDTMFEnteredArg_PDU,
      { "TDTMFEnteredArg", "ain.TDTMFEnteredArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_TMidCallArg_PDU,
      { "TMidCallArg", "ain.TMidCallArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_TNoAnswerArg_PDU,
      { "TNoAnswerArg", "ain.TNoAnswerArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_TerminationAttemptArg_PDU,
      { "TerminationAttemptArg", "ain.TerminationAttemptArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_TermResourceAvailableArg_PDU,
      { "TermResourceAvailableArg", "ain.TermResourceAvailableArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_TimeoutArg_PDU,
      { "TimeoutArg", "ain.TimeoutArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_AnalyzeRouteArg_PDU,
      { "AnalyzeRouteArg", "ain.AnalyzeRouteArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_AuthorizeTerminationArg_PDU,
      { "AuthorizeTerminationArg", "ain.AuthorizeTerminationArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_CancelResourceEventArg_PDU,
      { "CancelResourceEventArg", "ain.CancelResourceEventArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_CollectInformationArg_PDU,
      { "CollectInformationArg", "ain.CollectInformationArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_ConnectToResourceArg_PDU,
      { "ConnectToResourceArg", "ain.ConnectToResourceArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_ContinueArg_PDU,
      { "ContinueArg", "ain.ContinueArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_CreateCallArg_PDU,
      { "CreateCallArg", "ain.CreateCallArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_CreateCallRes_PDU,
      { "CreateCallRes", "ain.CreateCallRes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_DisconnectArg_PDU,
      { "DisconnectArg", "ain.DisconnectArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_DisconnectLegArg_PDU,
      { "DisconnectLegArg", "ain.DisconnectLegArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_ForwardCallArg_PDU,
      { "ForwardCallArg", "ain.ForwardCallArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_MergeCallArg_PDU,
      { "MergeCallArg", "ain.MergeCallArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_MoveLegArg_PDU,
      { "MoveLegArg", "ain.MoveLegArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_OfferCallArg_PDU,
      { "OfferCallArg", "ain.OfferCallArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_OriginateCallArg_PDU,
      { "OriginateCallArg", "ain.OriginateCallArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_ReconnectArg_PDU,
      { "ReconnectArg", "ain.ReconnectArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_SendToResourceArg_PDU,
      { "SendToResourceArg", "ain.SendToResourceArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_RES_sendToResource_PDU,
      { "RES-sendToResource", "ain.RES_sendToResource_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_SetTimerArg_PDU,
      { "SetTimerArg", "ain.SetTimerArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_TimerUpdated_PDU,
      { "TimerUpdated", "ain.TimerUpdated",
        FT_UINT32, BASE_DEC, VALS(ain_TimerUpdated_U_vals), 0,
        NULL, HFILL }},
    { &hf_ain_SplitLegArg_PDU,
      { "SplitLegArg", "ain.SplitLegArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_AcgArg_PDU,
      { "AcgArg", "ain.AcgArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_AcgGlobalCtrlRestoreArg_PDU,
      { "AcgGlobalCtrlRestoreArg", "ain.AcgGlobalCtrlRestoreArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_RES_acgGlobalCtrlRestore_PDU,
      { "RES-acgGlobalCtrlRestore", "ain.RES_acgGlobalCtrlRestore_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_AcgOverflowArg_PDU,
      { "AcgOverflowArg", "ain.AcgOverflowArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_ActivityTestArg_PDU,
      { "ActivityTestArg", "ain.ActivityTestArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_RES_activityTest_PDU,
      { "RES-activityTest", "ain.RES_activityTest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_CallTypeRequestArg_PDU,
      { "CallTypeRequestArg", "ain.CallTypeRequestArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_RES_callTypeRequest_PDU,
      { "RES-callTypeRequest", "ain.RES_callTypeRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_ControlRequestArg_PDU,
      { "ControlRequestArg", "ain.ControlRequestArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_EchoRequestArg_PDU,
      { "EchoRequestArg", "ain.EchoRequestArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_RES_echoRequest_PDU,
      { "RES-echoRequest", "ain.RES_echoRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_FurnishAMAInformationArg_PDU,
      { "FurnishAMAInformationArg", "ain.FurnishAMAInformationArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_MonitorForChangeArg_PDU,
      { "MonitorForChangeArg", "ain.MonitorForChangeArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_MonitorSuccessArg_PDU,
      { "MonitorSuccessArg", "ain.MonitorSuccessArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_NCADataArg_PDU,
      { "NCADataArg", "ain.NCADataArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_NCARequestArg_PDU,
      { "NCARequestArg", "ain.NCARequestArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_RES_nCARequest_PDU,
      { "RES-nCARequest", "ain.RES_nCARequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_QueryRequestArg_PDU,
      { "QueryRequestArg", "ain.QueryRequestArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_RES_queryRequest_PDU,
      { "RES-queryRequest", "ain.RES_queryRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_RequestReportBCMEventArg_PDU,
      { "RequestReportBCMEventArg", "ain.RequestReportBCMEventArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_StatusReportedArg_PDU,
      { "StatusReportedArg", "ain.StatusReportedArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_TerminationNotificationArg_PDU,
      { "TerminationNotificationArg", "ain.TerminationNotificationArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_UpdateArg_PDU,
      { "UpdateArg", "ain.UpdateArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_RES_update_PDU,
      { "RES-update", "ain.RES_update_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_UpdateRequestArg_PDU,
      { "UpdateRequestArg", "ain.UpdateRequestArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_RES_updateRequest_PDU,
      { "RES-updateRequest", "ain.RES_updateRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_PAR_applicationError_PDU,
      { "PAR-applicationError", "ain.PAR_applicationError_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_PAR_failureReport_PDU,
      { "PAR-failureReport", "ain.PAR_failureReport_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_iPReturnBlock,
      { "iPReturnBlock", "ain.iPReturnBlock",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_amp1,
      { "amp1", "ain.amp1",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_amp2,
      { "amp2", "ain.amp2_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_extensionParameter,
      { "extensionParameter", "ain.extensionParameter_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_userID,
      { "userID", "ain.userID",
        FT_UINT32, BASE_DEC, VALS(ain_UserID_U_vals), 0,
        NULL, HFILL }},
    { &hf_ain_bearerCapability,
      { "bearerCapability", "ain.bearerCapability",
        FT_UINT32, BASE_DEC, VALS(ain_BearerCapability_U_vals), 0,
        NULL, HFILL }},
    { &hf_ain_closeCause,
      { "closeCause", "ain.closeCause",
        FT_UINT32, BASE_DEC, VALS(ain_CloseCause_U_vals), 0,
        NULL, HFILL }},
    { &hf_ain_clearCause,
      { "clearCause", "ain.clearCause",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_legID,
      { "legID", "ain.legID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_ccID,
      { "ccID", "ain.ccID",
        FT_UINT32, BASE_DEC, VALS(ain_CcID_U_vals), 0,
        NULL, HFILL }},
    { &hf_ain_bCMType,
      { "bCMType", "ain.bCMType",
        FT_UINT32, BASE_DEC, VALS(ain_BCMType_U_vals), 0,
        NULL, HFILL }},
    { &hf_ain_pointInCall,
      { "pointInCall", "ain.pointInCall",
        FT_UINT32, BASE_DEC, VALS(ain_PointInCall_U_vals), 0,
        NULL, HFILL }},
    { &hf_ain_collectedDigits,
      { "collectedDigits", "ain.collectedDigits",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_collectedAddressInfo,
      { "collectedAddressInfo", "ain.collectedAddressInfo",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_carrier,
      { "carrier", "ain.carrier",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_failureCause,
      { "failureCause", "ain.failureCause",
        FT_UINT32, BASE_DEC, VALS(ain_FailureCause_U_vals), 0,
        NULL, HFILL }},
    { &hf_ain_aMAMeasurement,
      { "aMAMeasurement", "ain.aMAMeasurement_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_clearCauseData,
      { "clearCauseData", "ain.clearCauseData",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_notificationIndicator,
      { "notificationIndicator", "ain.notificationIndicator",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_calledPartyID,
      { "calledPartyID", "ain.calledPartyID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_lata,
      { "lata", "ain.lata",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_triggerCriteriaType,
      { "triggerCriteriaType", "ain.triggerCriteriaType",
        FT_UINT32, BASE_DEC, VALS(ain_TriggerCriteriaType_U_vals), 0,
        NULL, HFILL }},
    { &hf_ain_chargeNumber,
      { "chargeNumber", "ain.chargeNumber",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_callingPartyID,
      { "callingPartyID", "ain.callingPartyID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_callingPartyBGID,
      { "callingPartyBGID", "ain.callingPartyBGID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_chargePartyStationType,
      { "chargePartyStationType", "ain.chargePartyStationType",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_accessCode,
      { "accessCode", "ain.accessCode",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_verticalServiceCode,
      { "verticalServiceCode", "ain.verticalServiceCode",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_tcm,
      { "tcm", "ain.tcm",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_originalCalledPartyID,
      { "originalCalledPartyID", "ain.originalCalledPartyID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_redirectingPartyID,
      { "redirectingPartyID", "ain.redirectingPartyID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_redirectionInformation,
      { "redirectionInformation", "ain.redirectionInformation",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_aCGEncountered,
      { "aCGEncountered", "ain.aCGEncountered",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_sap,
      { "sap", "ain.sap",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_sTRConnection,
      { "sTRConnection", "ain.sTRConnection",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_aMASequenceNumber,
      { "aMASequenceNumber", "ain.aMASequenceNumber",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_genericAddressList,
      { "genericAddressList", "ain.genericAddressList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_networkSpecificFacilities,
      { "networkSpecificFacilities", "ain.networkSpecificFacilities",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_cTRConnection,
      { "cTRConnection", "ain.cTRConnection",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_jurisdictionInformation,
      { "jurisdictionInformation", "ain.jurisdictionInformation",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_prefix,
      { "prefix", "ain.prefix",
        FT_UINT32, BASE_DEC, VALS(ain_Prefix_U_vals), 0,
        NULL, HFILL }},
    { &hf_ain_callingGeodeticLocation,
      { "callingGeodeticLocation", "ain.callingGeodeticLocation",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_triggerInformation,
      { "triggerInformation", "ain.triggerInformation",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_disconnectCause,
      { "disconnectCause", "ain.disconnectCause",
        FT_UINT32, BASE_DEC, VALS(ain_DisconnectCause_U_vals), 0,
        NULL, HFILL }},
    { &hf_ain_featureActivatorID,
      { "featureActivatorID", "ain.featureActivatorID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_busyCause,
      { "busyCause", "ain.busyCause",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_busyType,
      { "busyType", "ain.busyType",
        FT_UINT32, BASE_DEC, VALS(ain_BusyType_U_vals), 0,
        NULL, HFILL }},
    { &hf_ain_calledPartyStationType,
      { "calledPartyStationType", "ain.calledPartyStationType",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_genericName,
      { "genericName", "ain.genericName",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_dTMFDigitsDetected,
      { "dTMFDigitsDetected", "ain.dTMFDigitsDetected",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_rTPServiceIndicator,
      { "rTPServiceIndicator", "ain.rTPServiceIndicator",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_outpulseNumber,
      { "outpulseNumber", "ain.outpulseNumber",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_primaryTrunkGroup,
      { "primaryTrunkGroup", "ain.primaryTrunkGroup",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_alternateTrunkGroup,
      { "alternateTrunkGroup", "ain.alternateTrunkGroup",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_secondAlternateTrunkGroup,
      { "secondAlternateTrunkGroup", "ain.secondAlternateTrunkGroup",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_alternateCarrier,
      { "alternateCarrier", "ain.alternateCarrier",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_secondAlternateCarrier,
      { "secondAlternateCarrier", "ain.secondAlternateCarrier",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_passiveLegTreatment,
      { "passiveLegTreatment", "ain.passiveLegTreatment",
        FT_UINT32, BASE_DEC, VALS(ain_PassiveLegTreatment_U_vals), 0,
        NULL, HFILL }},
    { &hf_ain_primaryBillingIndicator,
      { "primaryBillingIndicator", "ain.primaryBillingIndicator",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_alternateBillingIndicator,
      { "alternateBillingIndicator", "ain.alternateBillingIndicator",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_secondAlternateBillingIndicator,
      { "secondAlternateBillingIndicator", "ain.secondAlternateBillingIndicator",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_overflowBillingIndicator,
      { "overflowBillingIndicator", "ain.overflowBillingIndicator",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_aMAAlternateBillingNumber,
      { "aMAAlternateBillingNumber", "ain.aMAAlternateBillingNumber",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_aMABusinessCustomerID,
      { "aMABusinessCustomerID", "ain.aMABusinessCustomerID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_aMALineNumberList,
      { "aMALineNumberList", "ain.aMALineNumberList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_2_OF_AMALineNumber", HFILL }},
    { &hf_ain_aMALineNumberList_item,
      { "AMALineNumber", "ain.AMALineNumber",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_aMAslpID,
      { "aMAslpID", "ain.aMAslpID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_aMADigitsDialedWCList,
      { "aMADigitsDialedWCList", "ain.aMADigitsDialedWCList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_5_OF_AMADigitsDialedWC", HFILL }},
    { &hf_ain_aMADigitsDialedWCList_item,
      { "AMADigitsDialedWC", "ain.AMADigitsDialedWC",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_serviceProviderID,
      { "serviceProviderID", "ain.serviceProviderID",
        FT_UINT32, BASE_DEC, VALS(ain_ServiceProviderID_vals), 0,
        NULL, HFILL }},
    { &hf_ain_serviceContext,
      { "serviceContext", "ain.serviceContext",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_aMABillingFeature,
      { "aMABillingFeature", "ain.aMABillingFeature",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_carrierUsage,
      { "carrierUsage", "ain.carrierUsage",
        FT_UINT32, BASE_DEC, VALS(ain_CarrierUsage_U_vals), 0,
        NULL, HFILL }},
    { &hf_ain_forwardCallIndicator,
      { "forwardCallIndicator", "ain.forwardCallIndicator",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_aMAServiceProviderID,
      { "aMAServiceProviderID", "ain.aMAServiceProviderID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_genericDigitsList,
      { "genericDigitsList", "ain.genericDigitsList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_applyRestrictions,
      { "applyRestrictions", "ain.applyRestrictions",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_displayText,
      { "displayText", "ain.displayText",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_controllingLegTreatment,
      { "controllingLegTreatment", "ain.controllingLegTreatment",
        FT_UINT32, BASE_DEC, VALS(ain_ControllingLegTreatment_U_vals), 0,
        NULL, HFILL }},
    { &hf_ain_aMAserviceProviderID,
      { "aMAserviceProviderID", "ain.aMAserviceProviderID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_dPConverter,
      { "dPConverter", "ain.dPConverter",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_alternateDialingPlanInd,
      { "alternateDialingPlanInd", "ain.alternateDialingPlanInd",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_resourceType,
      { "resourceType", "ain.resourceType",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_strParameterBlock,
      { "strParameterBlock", "ain.strParameterBlock",
        FT_UINT32, BASE_DEC, VALS(ain_StrParameterBlock_U_vals), 0,
        NULL, HFILL }},
    { &hf_ain_disconnectFlag,
      { "disconnectFlag", "ain.disconnectFlag_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_destinationAddress,
      { "destinationAddress", "ain.destinationAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_aMAMeasure,
      { "aMAMeasure", "ain.aMAMeasure",
        FT_UINT32, BASE_DEC, VALS(ain_AMAMeasure_U_vals), 0,
        NULL, HFILL }},
    { &hf_ain_notificationDuration,
      { "notificationDuration", "ain.notificationDuration",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_wakeUpDuration,
      { "wakeUpDuration", "ain.wakeUpDuration",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_oSIIndicator,
      { "oSIIndicator", "ain.oSIIndicator",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_rTPReroutingNumber,
      { "rTPReroutingNumber", "ain.rTPReroutingNumber",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_csID,
      { "csID", "ain.csID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_lampTreatment,
      { "lampTreatment", "ain.lampTreatment",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_secondAlternatecarrier,
      { "secondAlternatecarrier", "ain.secondAlternatecarrier",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_answerIndicator,
      { "answerIndicator", "ain.answerIndicator_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_extendedRinging,
      { "extendedRinging", "ain.extendedRinging_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_tSTRCTimer,
      { "tSTRCTimer", "ain.tSTRCTimer",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_partyID,
      { "partyID", "ain.partyID",
        FT_UINT32, BASE_DEC, VALS(ain_PartyID_U_vals), 0,
        NULL, HFILL }},
    { &hf_ain_partyOnHold,
      { "partyOnHold", "ain.partyOnHold_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_sSPResponseMessageTimerT1,
      { "sSPResponseMessageTimerT1", "ain.sSPResponseMessageTimerT1",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_controlCauseIndicator,
      { "controlCauseIndicator", "ain.controlCauseIndicator",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_gapDuration,
      { "gapDuration", "ain.gapDuration",
        FT_UINT32, BASE_DEC, VALS(ain_GapDuration_U_vals), 0,
        NULL, HFILL }},
    { &hf_ain_gapInterval,
      { "gapInterval", "ain.gapInterval",
        FT_UINT32, BASE_DEC, VALS(ain_GapInterval_vals), 0,
        NULL, HFILL }},
    { &hf_ain_translationType,
      { "translationType", "ain.translationType",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_globalTitleAddress,
      { "globalTitleAddress", "ain.globalTitleAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_aCGGlobalOverride,
      { "aCGGlobalOverride", "ain.aCGGlobalOverride",
        FT_UINT32, BASE_DEC, VALS(ain_ACGGlobalOverride_U_vals), 0,
        NULL, HFILL }},
    { &hf_ain_actResult,
      { "actResult", "ain.actResult",
        FT_UINT32, BASE_DEC, VALS(ain_ActResult_U_vals), 0,
        NULL, HFILL }},
    { &hf_ain_transID,
      { "transID", "ain.transID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_callType,
      { "callType", "ain.callType",
        FT_UINT32, BASE_DEC, VALS(ain_CallType_U_vals), 0,
        NULL, HFILL }},
    { &hf_ain_congestionLevel,
      { "congestionLevel", "ain.congestionLevel",
        FT_UINT32, BASE_DEC, VALS(ain_CongestionLevel_U_vals), 0,
        NULL, HFILL }},
    { &hf_ain_ssignalingPointCode,
      { "ssignalingPointCode", "ain.ssignalingPointCode",
        FT_BYTES, BASE_NONE, NULL, 0,
        "SignalingPointCode", HFILL }},
    { &hf_ain_subsystemNumber,
      { "subsystemNumber", "ain.subsystemNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_applicationIndicator,
      { "applicationIndicator", "ain.applicationIndicator",
        FT_UINT32, BASE_DEC, VALS(ain_ApplicationIndicator_U_vals), 0,
        NULL, HFILL }},
    { &hf_ain_aaMABAFModules,
      { "aaMABAFModules", "ain.aaMABAFModules",
        FT_BYTES, BASE_NONE, NULL, 0,
        "AMABAFModules", HFILL }},
    { &hf_ain_aMASetHexABIndicator,
      { "aMASetHexABIndicator", "ain.aMASetHexABIndicator",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_facilityStatus,
      { "facilityStatus", "ain.facilityStatus",
        FT_UINT32, BASE_DEC, VALS(ain_FacilityStatus_U_vals), 0,
        NULL, HFILL }},
    { &hf_ain_monitorTime,
      { "monitorTime", "ain.monitorTime",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_facilityGID,
      { "facilityGID", "ain.facilityGID",
        FT_UINT32, BASE_DEC, VALS(ain_FacilityGID_vals), 0,
        NULL, HFILL }},
    { &hf_ain_facilityMemberID,
      { "facilityMemberID", "ain.facilityMemberID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_controlEncountered,
      { "controlEncountered", "ain.controlEncountered",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_id,
      { "id", "ain.id",
        FT_UINT32, BASE_DEC, VALS(ain_T_id_vals), 0,
        NULL, HFILL }},
    { &hf_ain_srhrGroupID,
      { "srhrGroupID", "ain.srhrGroupID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_envelopeEncodingAuthority,
      { "envelopeEncodingAuthority", "ain.envelopeEncodingAuthority",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_envelopContent,
      { "envelopContent", "ain.envelopContent",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_securityEnvelope,
      { "securityEnvelope", "ain.securityEnvelope",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_infoProvided,
      { "infoProvided", "ain.infoProvided_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_provideInfo,
      { "provideInfo", "ain.provideInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_eDPRequest,
      { "eDPRequest", "ain.eDPRequest",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_eDPNotification,
      { "eDPNotification", "ain.eDPNotification",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_oNoAnswerTimer,
      { "oNoAnswerTimer", "ain.oNoAnswerTimer",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_tNoAnswerTimer,
      { "tNoAnswerTimer", "ain.tNoAnswerTimer",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_timeoutTimer,
      { "timeoutTimer", "ain.timeoutTimer",
        FT_UINT32, BASE_DEC, VALS(ain_TimeoutTimer_U_vals), 0,
        NULL, HFILL }},
    { &hf_ain_oDTMFDigitsString,
      { "oDTMFDigitsString", "ain.oDTMFDigitsString",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_oDTMFNumberOfDigits,
      { "oDTMFNumberOfDigits", "ain.oDTMFNumberOfDigits",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_tDTMFDigitString,
      { "tDTMFDigitString", "ain.tDTMFDigitString",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_tDTMFNumberOfDigits,
      { "tDTMFNumberOfDigits", "ain.tDTMFNumberOfDigits",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_statusCause,
      { "statusCause", "ain.statusCause",
        FT_UINT32, BASE_DEC, VALS(ain_StatusCause_U_vals), 0,
        NULL, HFILL }},
    { &hf_ain_echoData,
      { "echoData", "ain.echoData",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_terminationIndicator,
      { "terminationIndicator", "ain.terminationIndicator",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_connectTime,
      { "connectTime", "ain.connectTime",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_resultCause,
      { "resultCause", "ain.resultCause",
        FT_UINT32, BASE_DEC, VALS(ain_ResultCause_U_vals), 0,
        NULL, HFILL }},
    { &hf_ain_administrableObject,
      { "administrableObject", "ain.administrableObject",
        FT_UINT32, BASE_DEC, VALS(ain_AdministrableObject_vals), 0,
        NULL, HFILL }},
    { &hf_ain_editListType,
      { "editListType", "ain.editListType",
        FT_UINT32, BASE_DEC, VALS(ain_EditListType_vals), 0,
        NULL, HFILL }},
    { &hf_ain_triggerCriteriaFlag,
      { "triggerCriteriaFlag", "ain.triggerCriteriaFlag",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_applicationErrorString,
      { "applicationErrorString", "ain.applicationErrorString_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_failureCauseData,
      { "failureCauseData", "ain.failureCauseData",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_triggerItemAssignment,
      { "triggerItemAssignment", "ain.triggerItemAssignment_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_sSPUserResource,
      { "sSPUserResource", "ain.sSPUserResource_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_srhrGroup,
      { "srhrGroup", "ain.srhrGroup_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_networkTestDesignator,
      { "networkTestDesignator", "ain.networkTestDesignator_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_operationsMonitoringAssignment,
      { "operationsMonitoringAssignment", "ain.operationsMonitoringAssignment_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_sSPUserResourceID,
      { "sSPUserResourceID", "ain.sSPUserResourceID",
        FT_UINT32, BASE_DEC, VALS(ain_SSPUserResourceID_vals), 0,
        NULL, HFILL }},
    { &hf_ain_triggerItemID,
      { "triggerItemID", "ain.triggerItemID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_activationStateCode,
      { "activationStateCode", "ain.activationStateCode",
        FT_UINT32, BASE_DEC, VALS(ain_ActivationStateCode_vals), 0,
        NULL, HFILL }},
    { &hf_ain_potentialUse,
      { "potentialUse", "ain.potentialUse",
        FT_UINT32, BASE_DEC, VALS(ain_PotentialUse_vals), 0,
        NULL, HFILL }},
    { &hf_ain_sSPUserResourceSubID,
      { "sSPUserResourceSubID", "ain.sSPUserResourceSubID",
        FT_UINT32, BASE_DEC, VALS(ain_SSPUserResourceSubID_vals), 0,
        NULL, HFILL }},
    { &hf_ain_dn,
      { "dn", "ain.dn",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_dnCtID,
      { "dnCtID", "ain.dnCtID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_spid,
      { "spid", "ain.spid",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_trunkGroupID,
      { "trunkGroupID", "ain.trunkGroupID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_localSSPID,
      { "localSSPID", "ain.localSSPID",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_publicDialingPlanID,
      { "publicDialingPlanID", "ain.publicDialingPlanID",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_pRIOfficeEquipmentID,
      { "pRIOfficeEquipmentID", "ain.pRIOfficeEquipmentID",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_basicBusinessGroupID,
      { "basicBusinessGroupID", "ain.basicBusinessGroupID",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_basicBusinessGroupDialingPlanID,
      { "basicBusinessGroupDialingPlanID", "ain.basicBusinessGroupDialingPlanID",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_aFRPatternID,
      { "aFRPatternID", "ain.aFRPatternID",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_officeEquipmentID,
      { "officeEquipmentID", "ain.officeEquipmentID",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_ct,
      { "ct", "ain.ct",
        FT_UINT32, BASE_DEC, VALS(ain_Ct_vals), 0,
        NULL, HFILL }},
    { &hf_ain_dPNumber,
      { "dPNumber", "ain.dPNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_triggerItemSubnumber,
      { "triggerItemSubnumber", "ain.triggerItemSubnumber",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_iSDNBChannelID,
      { "iSDNBChannelID", "ain.iSDNBChannelID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_pRIDS1ID,
      { "pRIDS1ID", "ain.pRIDS1ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_pRIDS0ID,
      { "pRIDS0ID", "ain.pRIDS0ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_updateGroups,
      { "updateGroups", "ain.updateGroups",
        FT_UINT32, BASE_DEC, VALS(ain_UpdateGroups_vals), 0,
        NULL, HFILL }},
    { &hf_ain_cancelInterdigitTimer,
      { "cancelInterdigitTimer", "ain.cancelInterdigitTimer",
        FT_UINT32, BASE_DEC, VALS(ain_ActivationStateCode_vals), 0,
        NULL, HFILL }},
    { &hf_ain_updateGroup1,
      { "updateGroup1", "ain.updateGroup1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_updateGroup2,
      { "updateGroup2", "ain.updateGroup2_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_updateGroup3,
      { "updateGroup3", "ain.updateGroup3_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_updateGroup4,
      { "updateGroup4", "ain.updateGroup4_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_updateGroup5,
      { "updateGroup5", "ain.updateGroup5_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_updateGroup6,
      { "updateGroup6", "ain.updateGroup6_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_updateGroup7,
      { "updateGroup7", "ain.updateGroup7_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_updateGroup8,
      { "updateGroup8", "ain.updateGroup8_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_updateGroup9,
      { "updateGroup9", "ain.updateGroup9_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_service1,
      { "service1", "ain.service1",
        FT_UINT32, BASE_DEC, VALS(ain_Service1_vals), 0,
        NULL, HFILL }},
    { &hf_ain_action1,
      { "action1", "ain.action1",
        FT_UINT32, BASE_DEC, VALS(ain_Action1_vals), 0,
        NULL, HFILL }},
    { &hf_ain_service2,
      { "service2", "ain.service2",
        FT_UINT32, BASE_DEC, VALS(ain_Service2_vals), 0,
        NULL, HFILL }},
    { &hf_ain_action2,
      { "action2", "ain.action2",
        FT_UINT32, BASE_DEC, VALS(ain_Action2_vals), 0,
        NULL, HFILL }},
    { &hf_ain_delayInterval,
      { "delayInterval", "ain.delayInterval",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_service3,
      { "service3", "ain.service3",
        FT_UINT32, BASE_DEC, VALS(ain_Service3_vals), 0,
        NULL, HFILL }},
    { &hf_ain_action3,
      { "action3", "ain.action3",
        FT_UINT32, BASE_DEC, VALS(ain_Action3_vals), 0,
        NULL, HFILL }},
    { &hf_ain_editSpecificEntry,
      { "editSpecificEntry", "ain.editSpecificEntry_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_editAllEntries,
      { "editAllEntries", "ain.editAllEntries",
        FT_UINT32, BASE_DEC, VALS(ain_EditAllEntries_vals), 0,
        NULL, HFILL }},
    { &hf_ain_entry,
      { "entry", "ain.entry",
        FT_UINT32, BASE_DEC, VALS(ain_Entry_vals), 0,
        NULL, HFILL }},
    { &hf_ain_speedCallingCode,
      { "speedCallingCode", "ain.speedCallingCode",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_memorySlot,
      { "memorySlot", "ain.memorySlot",
        FT_UINT32, BASE_DEC, VALS(ain_MemorySlot1_vals), 0,
        "MemorySlot1", HFILL }},
    { &hf_ain_service4,
      { "service4", "ain.service4",
        FT_UINT32, BASE_DEC, VALS(ain_Service4_vals), 0,
        NULL, HFILL }},
    { &hf_ain_action4,
      { "action4", "ain.action4",
        FT_UINT32, BASE_DEC, VALS(ain_Action4_vals), 0,
        NULL, HFILL }},
    { &hf_ain_forwardingDn,
      { "forwardingDn", "ain.forwardingDn",
        FT_UINT32, BASE_DEC, VALS(ain_ForwardingDn_vals), 0,
        NULL, HFILL }},
    { &hf_ain_set,
      { "set", "ain.set",
        FT_UINT32, BASE_DEC, VALS(ain_Set_vals), 0,
        NULL, HFILL }},
    { &hf_ain_clear,
      { "clear", "ain.clear",
        FT_UINT32, BASE_DEC, VALS(ain_Clear_vals), 0,
        NULL, HFILL }},
    { &hf_ain_service5,
      { "service5", "ain.service5",
        FT_UINT32, BASE_DEC, VALS(ain_Service5_vals), 0,
        NULL, HFILL }},
    { &hf_ain_action5,
      { "action5", "ain.action5",
        FT_UINT32, BASE_DEC, VALS(ain_Action5_vals), 0,
        NULL, HFILL }},
    { &hf_ain_service6,
      { "service6", "ain.service6",
        FT_UINT32, BASE_DEC, VALS(ain_Service6_vals), 0,
        NULL, HFILL }},
    { &hf_ain_action6,
      { "action6", "ain.action6",
        FT_UINT32, BASE_DEC, VALS(ain_Action6_vals), 0,
        NULL, HFILL }},
    { &hf_ain_service7,
      { "service7", "ain.service7",
        FT_UINT32, BASE_DEC, VALS(ain_Service7_vals), 0,
        NULL, HFILL }},
    { &hf_ain_action7,
      { "action7", "ain.action7",
        FT_UINT32, BASE_DEC, VALS(ain_Action7_vals), 0,
        NULL, HFILL }},
    { &hf_ain_toggle,
      { "toggle", "ain.toggle",
        FT_UINT32, BASE_DEC, VALS(ain_Toggle_vals), 0,
        NULL, HFILL }},
    { &hf_ain_service8,
      { "service8", "ain.service8",
        FT_UINT32, BASE_DEC, VALS(ain_Service8_vals), 0,
        NULL, HFILL }},
    { &hf_ain_action8,
      { "action8", "ain.action8",
        FT_UINT32, BASE_DEC, VALS(ain_Action8_vals), 0,
        NULL, HFILL }},
    { &hf_ain_action8_invoke,
      { "invoke", "ain.action8.invoke",
        FT_UINT32, BASE_DEC, VALS(ain_Invoke8_vals), 0,
        "Invoke8", HFILL }},
    { &hf_ain_service9,
      { "service9", "ain.service9",
        FT_UINT32, BASE_DEC, VALS(ain_Service9_vals), 0,
        NULL, HFILL }},
    { &hf_ain_action9,
      { "action9", "ain.action9",
        FT_UINT32, BASE_DEC, VALS(ain_Action9_vals), 0,
        NULL, HFILL }},
    { &hf_ain_changeList,
      { "changeList", "ain.changeList_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_srhrID,
      { "srhrID", "ain.srhrID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_ntdID,
      { "ntdID", "ain.ntdID",
        FT_UINT32, BASE_DEC, VALS(ain_NtdID_vals), 0,
        NULL, HFILL }},
    { &hf_ain_ntdIndirectID,
      { "ntdIndirectID", "ain.ntdIndirectID",
        FT_UINT32, BASE_DEC, VALS(ain_SSPUserResourceID_vals), 0,
        NULL, HFILL }},
    { &hf_ain_operationsMonitoredItemID,
      { "operationsMonitoredItemID", "ain.operationsMonitoredItemID",
        FT_UINT32, BASE_DEC, VALS(ain_OperationsMonitoredItemID_vals), 0,
        NULL, HFILL }},
    { &hf_ain_aMATimeDuration,
      { "aMATimeDuration", "ain.aMATimeDuration",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_aMATimeGuard,
      { "aMATimeGuard", "ain.aMATimeGuard",
        FT_UINT32, BASE_DEC, VALS(ain_AMATimeGuard_vals), 0,
        NULL, HFILL }},
    { &hf_ain_ampAINNodeID,
      { "ampAINNodeID", "ain.ampAINNodeID",
        FT_UINT32, BASE_DEC, VALS(ain_AmpAINNodeID_vals), 0,
        NULL, HFILL }},
    { &hf_ain_ampCLogSeqNo,
      { "ampCLogSeqNo", "ain.ampCLogSeqNo",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_ampCLogRepInd,
      { "ampCLogRepInd", "ain.ampCLogRepInd",
        FT_UINT32, BASE_DEC, VALS(ain_AmpCLogRepInd_vals), 0,
        NULL, HFILL }},
    { &hf_ain_ampCallProgInd,
      { "ampCallProgInd", "ain.ampCallProgInd",
        FT_UINT32, BASE_DEC, VALS(ain_AmpCallProgInd_vals), 0,
        NULL, HFILL }},
    { &hf_ain_ampTestReqInd,
      { "ampTestReqInd", "ain.ampTestReqInd",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_ampCLogName,
      { "ampCLogName", "ain.ampCLogName",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_ampSvcProvID,
      { "ampSvcProvID", "ain.ampSvcProvID",
        FT_UINT32, BASE_DEC, VALS(ain_AmpSvcProvID_vals), 0,
        NULL, HFILL }},
    { &hf_ain_spcID,
      { "spcID", "ain.spcID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_iSDNDeviceID,
      { "iSDNDeviceID", "ain.iSDNDeviceID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_ocn,
      { "ocn", "ain.ocn",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_errorCause,
      { "errorCause", "ain.errorCause",
        FT_UINT32, BASE_DEC, VALS(ain_ErrorCause_U_vals), 0,
        NULL, HFILL }},
    { &hf_ain_failedMessage,
      { "failedMessage", "ain.failedMessage_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain__untag_item,
      { "DisplayInformation", "ain.DisplayInformation",
        FT_UINT32, BASE_DEC, VALS(ain_DisplayInformation_vals), 0,
        NULL, HFILL }},
    { &hf_ain_blank,
      { "blank", "ain.blank",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_20", HFILL }},
    { &hf_ain_skip,
      { "skip", "ain.skip",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_20", HFILL }},
    { &hf_ain_continuation,
      { "continuation", "ain.continuation",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_20", HFILL }},
    { &hf_ain_calledAddress,
      { "calledAddress", "ain.calledAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_20", HFILL }},
    { &hf_ain_cause,
      { "cause", "ain.cause",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_20", HFILL }},
    { &hf_ain_progressIndicator,
      { "progressIndicator", "ain.progressIndicator",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_20", HFILL }},
    { &hf_ain_displayInformation_notificationIndicator,
      { "notificationIndicator", "ain.displayInformation.notificationIndicator",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_20", HFILL }},
    { &hf_ain_prompt,
      { "prompt", "ain.prompt",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_20", HFILL }},
    { &hf_ain_accumulatedDigits,
      { "accumulatedDigits", "ain.accumulatedDigits",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_20", HFILL }},
    { &hf_ain_status,
      { "status", "ain.status",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_20", HFILL }},
    { &hf_ain_inband,
      { "inband", "ain.inband",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_20", HFILL }},
    { &hf_ain_callingAddress,
      { "callingAddress", "ain.callingAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_20", HFILL }},
    { &hf_ain_reason,
      { "reason", "ain.reason",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_20", HFILL }},
    { &hf_ain_callingPartyName,
      { "callingPartyName", "ain.callingPartyName",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_20", HFILL }},
    { &hf_ain_calledPartyName,
      { "calledPartyName", "ain.calledPartyName",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_20", HFILL }},
    { &hf_ain_originalCalledName,
      { "originalCalledName", "ain.originalCalledName",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_20", HFILL }},
    { &hf_ain_redirectingName,
      { "redirectingName", "ain.redirectingName",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_20", HFILL }},
    { &hf_ain_connectedName,
      { "connectedName", "ain.connectedName",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_20", HFILL }},
    { &hf_ain_origRestrictions,
      { "origRestrictions", "ain.origRestrictions",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_20", HFILL }},
    { &hf_ain_dateTimeOfDay,
      { "dateTimeOfDay", "ain.dateTimeOfDay",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_20", HFILL }},
    { &hf_ain_callAppearanceID,
      { "callAppearanceID", "ain.callAppearanceID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_20", HFILL }},
    { &hf_ain_featureAddress,
      { "featureAddress", "ain.featureAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_20", HFILL }},
    { &hf_ain_redirectionName,
      { "redirectionName", "ain.redirectionName",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_20", HFILL }},
    { &hf_ain_redirectionNumber,
      { "redirectionNumber", "ain.redirectionNumber",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_20", HFILL }},
    { &hf_ain_redirectingNumber,
      { "redirectingNumber", "ain.redirectingNumber",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_20", HFILL }},
    { &hf_ain_originalCalledNumber,
      { "originalCalledNumber", "ain.originalCalledNumber",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_20", HFILL }},
    { &hf_ain_connectedNumber,
      { "connectedNumber", "ain.connectedNumber",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_20", HFILL }},
    { &hf_ain_text,
      { "text", "ain.text",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_20", HFILL }},
    { &hf_ain_redirectingReason,
      { "redirectingReason", "ain.redirectingReason",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_20", HFILL }},
    { &hf_ain_assignmentAuthority,
      { "assignmentAuthority", "ain.assignmentAuthority",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_parameters,
      { "parameters", "ain.parameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_mlhg,
      { "mlhg", "ain.mlhg",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_opCode,
      { "opCode", "ain.opCode",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_ain_parameter,
      { "parameter", "ain.parameter",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_ain_invParms,
      { "invParms", "ain.invParms",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_InvParms_item,
      { "Parms", "ain.Parms",
        FT_UINT32, BASE_DEC, VALS(ain_Parms_vals), 0,
        NULL, HFILL }},
    { &hf_ain_oDTMFNumberofDigits,
      { "oDTMFNumberofDigits", "ain.oDTMFNumberofDigits",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_timerUpdated,
      { "timerUpdated", "ain.timerUpdated",
        FT_UINT32, BASE_DEC, VALS(ain_TimerUpdated_U_vals), 0,
        NULL, HFILL }},
    { &hf_ain_derviceProviderID,
      { "derviceProviderID", "ain.derviceProviderID",
        FT_UINT32, BASE_DEC, VALS(ain_ServiceProviderID_vals), 0,
        "ServiceProviderID", HFILL }},
    { &hf_ain_aMABAFModules,
      { "aMABAFModules", "ain.aMABAFModules",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_aMALineNumber,
      { "aMALineNumber", "ain.aMALineNumber",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_aMADigitsDialedWC,
      { "aMADigitsDialedWC", "ain.aMADigitsDialedWC",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_genericAddress,
      { "genericAddress", "ain.genericAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_signalingPointCode,
      { "signalingPointCode", "ain.signalingPointCode",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_nationalGapInterval,
      { "nationalGapInterval", "ain.nationalGapInterval",
        FT_UINT32, BASE_DEC, VALS(ain_NationalGapInterval_U_vals), 0,
        NULL, HFILL }},
    { &hf_ain_privateGapInterval,
      { "privateGapInterval", "ain.privateGapInterval",
        FT_UINT32, BASE_DEC, VALS(ain_PrivateGapInterval_U_vals), 0,
        NULL, HFILL }},
    { &hf_ain__untag_item_01,
      { "GenericAddress", "ain.GenericAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain__untag_item_02,
      { "GenericDigits", "ain.GenericDigits",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_entireList,
      { "entireList", "ain.entireList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_memorySlot_01,
      { "memorySlot", "ain.memorySlot_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_listSize,
      { "listSize", "ain.listSize",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_forwardToDn,
      { "forwardToDn", "ain.forwardToDn",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_empty,
      { "empty", "ain.empty",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_EntireList_item,
      { "Entry2", "ain.Entry2",
        FT_UINT32, BASE_DEC, VALS(ain_Entry2_vals), 0,
        NULL, HFILL }},
    { &hf_ain_privateDn,
      { "privateDn", "ain.privateDn",
        FT_UINT32, BASE_DEC, VALS(ain_PrivateDn_vals), 0,
        NULL, HFILL }},
    { &hf_ain_incoming,
      { "incoming", "ain.incoming_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_outgoing,
      { "outgoing", "ain.outgoing_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_aINDigits,
      { "aINDigits", "ain.aINDigits",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_timestamp,
      { "timestamp", "ain.timestamp",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_requestGroups,
      { "requestGroups", "ain.requestGroups",
        FT_UINT32, BASE_DEC, VALS(ain_RequestGroups_vals), 0,
        NULL, HFILL }},
    { &hf_ain_requestMemorySlot,
      { "requestMemorySlot", "ain.requestMemorySlot",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_requestGroup1,
      { "requestGroup1", "ain.requestGroup1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_requestGroup2,
      { "requestGroup2", "ain.requestGroup2_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_requestGroup3,
      { "requestGroup3", "ain.requestGroup3_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_requestGroup4,
      { "requestGroup4", "ain.requestGroup4_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_requestGroup5,
      { "requestGroup5", "ain.requestGroup5_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_requestGroup6,
      { "requestGroup6", "ain.requestGroup6_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_request1,
      { "request1", "ain.request1",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_request2,
      { "request2", "ain.request2",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_request3,
      { "request3", "ain.request3",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_request4,
      { "request4", "ain.request4",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_request5,
      { "request5", "ain.request5",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_request6,
      { "request6", "ain.request6",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_msrID,
      { "msrID", "ain.msrID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_announcementBlock,
      { "announcementBlock", "ain.announcementBlock_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_announcementDigitBlock,
      { "announcementDigitBlock", "ain.announcementDigitBlock_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_flexParameterBlock,
      { "flexParameterBlock", "ain.flexParameterBlock",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_uninterAnnounceBlock,
      { "uninterAnnounceBlock", "ain.uninterAnnounceBlock",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_interAnnounceBlock,
      { "interAnnounceBlock", "ain.interAnnounceBlock",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_UninterAnnounceBlock_item,
      { "AnnounceElement", "ain.AnnounceElement",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_InterAnnounceBlock_item,
      { "AnnounceElement", "ain.AnnounceElement",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_maximumDigits,
      { "maximumDigits", "ain.maximumDigits",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_intervalTime,
      { "intervalTime", "ain.intervalTime",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_localSSPTime,
      { "localSSPTime", "ain.localSSPTime",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_absoluteSCPTime,
      { "absoluteSCPTime", "ain.absoluteSCPTime",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_bri,
      { "bri", "ain.bri_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_privateFacilityGID,
      { "privateFacilityGID", "ain.privateFacilityGID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_aDSIcpeID,
      { "aDSIcpeID", "ain.aDSIcpeID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_local,
      { "local", "ain.local",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_global,
      { "global", "ain.global",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_ain_invoke,
      { "invoke", "ain.invoke_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_returnResult,
      { "returnResult", "ain.returnResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_returnError,
      { "returnError", "ain.returnError_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_reject,
      { "reject", "ain.reject_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_invokeId,
      { "invokeId", "ain.invokeId",
        FT_UINT32, BASE_DEC, VALS(ain_InvokeId_vals), 0,
        NULL, HFILL }},
    { &hf_ain_linkedId,
      { "linkedId", "ain.linkedId",
        FT_UINT32, BASE_DEC, VALS(ain_T_linkedId_vals), 0,
        NULL, HFILL }},
    { &hf_ain_present,
      { "present", "ain.present",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_absent,
      { "absent", "ain.absent_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_opcode,
      { "opcode", "ain.opcode",
        FT_UINT32, BASE_DEC, VALS(ain_Code_vals), 0,
        "Code", HFILL }},
    { &hf_ain_argument,
      { "argument", "ain.argument_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_result,
      { "result", "ain.result_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_result_01,
      { "result", "ain.result_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_result_01", HFILL }},
    { &hf_ain_errcode,
      { "errcode", "ain.errcode",
        FT_UINT32, BASE_DEC, VALS(ain_Code_vals), 0,
        "Code", HFILL }},
    { &hf_ain_parameter_01,
      { "parameter", "ain.parameter_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ain_problem,
      { "problem", "ain.problem",
        FT_UINT32, BASE_DEC, VALS(ain_T_problem_vals), 0,
        NULL, HFILL }},
    { &hf_ain_general,
      { "general", "ain.general",
        FT_INT32, BASE_DEC, VALS(ain_GeneralProblem_vals), 0,
        "GeneralProblem", HFILL }},
    { &hf_ain_invokeproblem,
      { "invoke", "ain.invokeproblem",
        FT_INT32, BASE_DEC, VALS(ain_InvokeProblem_vals), 0,
        "InvokeProblem", HFILL }},
    { &hf_ain_returnResult_01,
      { "returnResult", "ain.returnResult",
        FT_INT32, BASE_DEC, VALS(ain_ReturnResultProblem_vals), 0,
        "ReturnResultProblem", HFILL }},
    { &hf_ain_returnError_01,
      { "returnError", "ain.returnError",
        FT_INT32, BASE_DEC, VALS(ain_ReturnErrorProblem_vals), 0,
        "ReturnErrorProblem", HFILL }},
    { &hf_ain_present_01,
      { "present", "ain.present",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_ain_InvokeId_present,
      { "InvokeId.present", "ain.InvokeId_present",
        FT_INT32, BASE_DEC, NULL, 0,
        "InvokeId_present", HFILL }},
    { &hf_ain_ApplyRestrictions_U_code,
      { "code", "ain.ApplyRestrictions.U.code",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_ain_ApplyRestrictions_U_toll,
      { "toll", "ain.ApplyRestrictions.U.toll",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_ain_EDPNotification_U_oCalledPartyBusy,
      { "oCalledPartyBusy", "ain.EDPNotification.U.oCalledPartyBusy",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_ain_EDPNotification_U_oNoAnswer,
      { "oNoAnswer", "ain.EDPNotification.U.oNoAnswer",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_ain_EDPNotification_U_oTermSeized,
      { "oTermSeized", "ain.EDPNotification.U.oTermSeized",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_ain_EDPNotification_U_oAnswer,
      { "oAnswer", "ain.EDPNotification.U.oAnswer",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_ain_EDPNotification_U_tBusy,
      { "tBusy", "ain.EDPNotification.U.tBusy",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_ain_EDPNotification_U_tNoAnswer,
      { "tNoAnswer", "ain.EDPNotification.U.tNoAnswer",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_ain_EDPNotification_U_termResourceAvailable,
      { "termResourceAvailable", "ain.EDPNotification.U.termResourceAvailable",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_ain_EDPNotification_U_tAnswer,
      { "tAnswer", "ain.EDPNotification.U.tAnswer",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_ain_EDPNotification_U_networkBusy,
      { "networkBusy", "ain.EDPNotification.U.networkBusy",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_ain_EDPNotification_U_oSuspended,
      { "oSuspended", "ain.EDPNotification.U.oSuspended",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_ain_EDPNotification_U_oDisconnectCalled,
      { "oDisconnectCalled", "ain.EDPNotification.U.oDisconnectCalled",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_ain_EDPNotification_U_oDisconnect,
      { "oDisconnect", "ain.EDPNotification.U.oDisconnect",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_ain_EDPNotification_U_oAbandon,
      { "oAbandon", "ain.EDPNotification.U.oAbandon",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_ain_EDPNotification_U_featureActivator,
      { "featureActivator", "ain.EDPNotification.U.featureActivator",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_ain_EDPNotification_U_switchHookFlash,
      { "switchHookFlash", "ain.EDPNotification.U.switchHookFlash",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_ain_EDPNotification_U_success,
      { "success", "ain.EDPNotification.U.success",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_ain_EDPNotification_U_tDisconnect,
      { "tDisconnect", "ain.EDPNotification.U.tDisconnect",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_ain_EDPNotification_U_timeout,
      { "timeout", "ain.EDPNotification.U.timeout",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_ain_EDPNotification_U_originationAttempt,
      { "originationAttempt", "ain.EDPNotification.U.originationAttempt",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_ain_EDPNotification_U_oDTMFEntered,
      { "oDTMFEntered", "ain.EDPNotification.U.oDTMFEntered",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_ain_EDPNotification_U_tDTMFEntered,
      { "tDTMFEntered", "ain.EDPNotification.U.tDTMFEntered",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_ain_EDPRequest_U_oCalledPartyBusy,
      { "oCalledPartyBusy", "ain.EDPRequest.U.oCalledPartyBusy",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_ain_EDPRequest_U_oNoAnswer,
      { "oNoAnswer", "ain.EDPRequest.U.oNoAnswer",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_ain_EDPRequest_U_oTermSeized,
      { "oTermSeized", "ain.EDPRequest.U.oTermSeized",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_ain_EDPRequest_U_oAnswer,
      { "oAnswer", "ain.EDPRequest.U.oAnswer",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_ain_EDPRequest_U_tBusy,
      { "tBusy", "ain.EDPRequest.U.tBusy",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_ain_EDPRequest_U_tNoAnswer,
      { "tNoAnswer", "ain.EDPRequest.U.tNoAnswer",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_ain_EDPRequest_U_termResourceAvailable,
      { "termResourceAvailable", "ain.EDPRequest.U.termResourceAvailable",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_ain_EDPRequest_U_tAnswer,
      { "tAnswer", "ain.EDPRequest.U.tAnswer",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_ain_EDPRequest_U_networkBusy,
      { "networkBusy", "ain.EDPRequest.U.networkBusy",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_ain_EDPRequest_U_oSuspended,
      { "oSuspended", "ain.EDPRequest.U.oSuspended",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_ain_EDPRequest_U_oDisconnectCalled,
      { "oDisconnectCalled", "ain.EDPRequest.U.oDisconnectCalled",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_ain_EDPRequest_U_oDisconnect,
      { "oDisconnect", "ain.EDPRequest.U.oDisconnect",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_ain_EDPRequest_U_oAbandon,
      { "oAbandon", "ain.EDPRequest.U.oAbandon",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_ain_EDPRequest_U_featureActivator,
      { "featureActivator", "ain.EDPRequest.U.featureActivator",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_ain_EDPRequest_U_switchHookFlash,
      { "switchHookFlash", "ain.EDPRequest.U.switchHookFlash",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_ain_EDPRequest_U_success,
      { "success", "ain.EDPRequest.U.success",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_ain_EDPRequest_U_tDisconnect,
      { "tDisconnect", "ain.EDPRequest.U.tDisconnect",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_ain_EDPRequest_U_timeout,
      { "timeout", "ain.EDPRequest.U.timeout",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_ain_EDPRequest_U_originationAttempt,
      { "originationAttempt", "ain.EDPRequest.U.originationAttempt",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_ain_EDPRequest_U_oDTMFEntered,
      { "oDTMFEntered", "ain.EDPRequest.U.oDTMFEntered",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_ain_EDPRequest_U_tDTMFEntered,
      { "tDTMFEntered", "ain.EDPRequest.U.tDTMFEntered",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_ain_Empty_entireList,
      { "entireList", "ain.Empty.entireList",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_ain_Empty_outgoingmemorySlot,
      { "outgoingmemorySlot", "ain.Empty.outgoingmemorySlot",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_ain_Empty_incomingmemorySlot,
      { "incomingmemorySlot", "ain.Empty.incomingmemorySlot",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_ain_Empty_forwardToDn,
      { "forwardToDn", "ain.Empty.forwardToDn",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_ain_Request1_activationStatus,
      { "activationStatus", "ain.Request1.activationStatus",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_ain_Request2_activationStatus,
      { "activationStatus", "ain.Request2.activationStatus",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_ain_Request2_delayInterval,
      { "delayInterval", "ain.Request2.delayInterval",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_ain_Request3_activationStatus,
      { "activationStatus", "ain.Request3.activationStatus",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_ain_Request3_entireList,
      { "entireList", "ain.Request3.entireList",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_ain_Request3_listSize,
      { "listSize", "ain.Request3.listSize",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_ain_Request4_activationStatus,
      { "activationStatus", "ain.Request4.activationStatus",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_ain_Request4_forwardingDn,
      { "forwardingDn", "ain.Request4.forwardingDn",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_ain_Request5_activationStatus,
      { "activationStatus", "ain.Request5.activationStatus",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_ain_Request5_forwardingDn,
      { "forwardingDn", "ain.Request5.forwardingDn",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_ain_Request5_entireList,
      { "entireList", "ain.Request5.entireList",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_ain_Request5_listSize,
      { "listSize", "ain.Request5.listSize",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_ain_Request6_delayInterval,
      { "delayInterval", "ain.Request6.delayInterval",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_ain_RequestMemorySlot_incoming,
      { "incoming", "ain.RequestMemorySlot.incoming",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_ain_RequestMemorySlot_outgoing,
      { "outgoing", "ain.RequestMemorySlot.outgoing",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    };

    /* List of subtrees */
    static int *ett[] = {
        &ett_ain,
        &ett_ain_digits,
        &ett_ain_carrierformat,
        &ett_ain_amaslpid,
    &ett_ain_CallInfoFromResourceArg,
    &ett_ain_CloseArg,
    &ett_ain_CTRClearArg,
    &ett_ain_FailureOutcomeArg,
    &ett_ain_InfoAnalyzedArg,
    &ett_ain_InfoCollectedArg,
    &ett_ain_NetworkBusyArg,
    &ett_ain_OAnswerArg,
    &ett_ain_OAbandonArg,
    &ett_ain_ODisconnectArg,
    &ett_ain_OMidCallArg,
    &ett_ain_ONoAnswerArg,
    &ett_ain_OSuspendedArg,
    &ett_ain_OTermSeizedArg,
    &ett_ain_OriginationAttemptArg,
    &ett_ain_RES_resourceClear,
    &ett_ain_ResourceClearArg,
    &ett_ain_SuccessOutcomeArg,
    &ett_ain_TAnswerArg,
    &ett_ain_TBusyArg,
    &ett_ain_TDisconnectArg,
    &ett_ain_TDTMFEnteredArg,
    &ett_ain_TMidCallArg,
    &ett_ain_TNoAnswerArg,
    &ett_ain_TerminationAttemptArg,
    &ett_ain_TermResourceAvailableArg,
    &ett_ain_TimeoutArg,
    &ett_ain_AnalyzeRouteArg,
    &ett_ain_SEQUENCE_SIZE_1_2_OF_AMALineNumber,
    &ett_ain_SEQUENCE_SIZE_1_5_OF_AMADigitsDialedWC,
    &ett_ain_AuthorizeTerminationArg,
    &ett_ain_CancelResourceEventArg,
    &ett_ain_CollectInformationArg,
    &ett_ain_ConnectToResourceArg,
    &ett_ain_ContinueArg,
    &ett_ain_CreateCallArg,
    &ett_ain_CreateCallRes,
    &ett_ain_DisconnectArg,
    &ett_ain_DisconnectLegArg,
    &ett_ain_ForwardCallArg,
    &ett_ain_MergeCallArg,
    &ett_ain_MoveLegArg,
    &ett_ain_OfferCallArg,
    &ett_ain_OriginateCallArg,
    &ett_ain_ReconnectArg,
    &ett_ain_RES_sendToResource,
    &ett_ain_SendToResourceArg,
    &ett_ain_SetTimerArg,
    &ett_ain_SplitLegArg,
    &ett_ain_AcgArg,
    &ett_ain_RES_acgGlobalCtrlRestore,
    &ett_ain_AcgGlobalCtrlRestoreArg,
    &ett_ain_AcgOverflowArg,
    &ett_ain_RES_activityTest,
    &ett_ain_ActivityTestArg,
    &ett_ain_RES_callTypeRequest,
    &ett_ain_CallTypeRequestArg,
    &ett_ain_ControlRequestArg,
    &ett_ain_RES_echoRequest,
    &ett_ain_EchoRequestArg,
    &ett_ain_FurnishAMAInformationArg,
    &ett_ain_MonitorForChangeArg,
    &ett_ain_MonitorSuccessArg,
    &ett_ain_NCADataArg,
    &ett_ain_T_id,
    &ett_ain_RES_nCARequest,
    &ett_ain_NCARequestArg,
    &ett_ain_RES_queryRequest,
    &ett_ain_QueryRequestArg,
    &ett_ain_RequestReportBCMEventArg,
    &ett_ain_StatusReportedArg,
    &ett_ain_TerminationNotificationArg,
    &ett_ain_RES_update,
    &ett_ain_UpdateArg,
    &ett_ain_RES_updateRequest,
    &ett_ain_UpdateRequestArg,
    &ett_ain_PAR_applicationError,
    &ett_ain_PAR_failureReport,
    &ett_ain_AdministrableObject,
    &ett_ain_TriggerItemAssignment_U,
    &ett_ain_SSPUserResourceID,
    &ett_ain_DnCtID,
    &ett_ain_TriggerItemID,
    &ett_ain_SSPUserResourceSubID,
    &ett_ain_ISDNBChannelID,
    &ett_ain_SSPUserResource_U,
    &ett_ain_UpdateGroups,
    &ett_ain_UpdateGroup1,
    &ett_ain_Action1,
    &ett_ain_UpdateGroup2,
    &ett_ain_Action2,
    &ett_ain_UpdateGroup3,
    &ett_ain_Action3,
    &ett_ain_EditSpecificEntry,
    &ett_ain_Entry,
    &ett_ain_UpdateGroup4,
    &ett_ain_Action4,
    &ett_ain_ForwardingDn,
    &ett_ain_Set,
    &ett_ain_UpdateGroup5,
    &ett_ain_Action5,
    &ett_ain_UpdateGroup6,
    &ett_ain_Action6,
    &ett_ain_UpdateGroup7,
    &ett_ain_Action7,
    &ett_ain_UpdateGroup8,
    &ett_ain_Action8,
    &ett_ain_UpdateGroup9,
    &ett_ain_Action9,
    &ett_ain_ChangeList,
    &ett_ain_SrhrGroup_U,
    &ett_ain_NetworkTestDesignator_U,
    &ett_ain_NtdID,
    &ett_ain_OperationsMonitoringAssignment_U,
    &ett_ain_OperationsMonitoredItemID,
    &ett_ain_AMAMeasurement_U,
    &ett_ain_Amp2_U,
    &ett_ain_AmpAINNodeID,
    &ett_ain_AmpSvcProvID,
    &ett_ain_ApplicationErrorString_U,
    &ett_ain_ApplyRestrictions_U,
    &ett_ain_SEQUENCE_SIZE_1_15_OF_DisplayInformation,
    &ett_ain_DisplayInformation,
    &ett_ain_EDPNotification_U,
    &ett_ain_EDPRequest_U,
    &ett_ain_ExtensionParameter,
    &ett_ain_FacilityGID,
    &ett_ain_FailedMessage_U,
    &ett_ain_InvParms,
    &ett_ain_Parms,
    &ett_ain_GapInterval,
    &ett_ain_SEQUENCE_SIZE_1_5_OF_GenericAddress,
    &ett_ain_SEQUENCE_SIZE_1_5_OF_GenericDigits,
    &ett_ain_InfoProvided_U,
    &ett_ain_EntireList,
    &ett_ain_Entry2,
    &ett_ain_MemorySlot,
    &ett_ain_Incoming,
    &ett_ain_Outgoing,
    &ett_ain_Empty,
    &ett_ain_ProvideInfo_U,
    &ett_ain_RequestGroups,
    &ett_ain_RequestGroup1,
    &ett_ain_Request1,
    &ett_ain_RequestGroup2,
    &ett_ain_Request2,
    &ett_ain_RequestGroup3,
    &ett_ain_Request3,
    &ett_ain_RequestGroup4,
    &ett_ain_Request4,
    &ett_ain_RequestGroup5,
    &ett_ain_Request5,
    &ett_ain_RequestGroup6,
    &ett_ain_Request6,
    &ett_ain_RequestMemorySlot,
    &ett_ain_ServiceProviderID,
    &ett_ain_StrParameterBlock_U,
    &ett_ain_AnnouncementBlock,
    &ett_ain_UninterAnnounceBlock,
    &ett_ain_InterAnnounceBlock,
    &ett_ain_AnnouncementDigitBlock,
    &ett_ain_TimeoutTimer_U,
    &ett_ain_UserID_U,
    &ett_ain_T_bri,
    &ett_ain_Code,
    &ett_ain_ROS,
    &ett_ain_Invoke,
    &ett_ain_T_linkedId,
    &ett_ain_ReturnResult,
    &ett_ain_T_result,
    &ett_ain_ReturnError,
    &ett_ain_Reject,
    &ett_ain_T_problem,
    &ett_ain_InvokeId,
    };

    static ei_register_info ei[] = {
        { &ei_ain_unknown_invokeData,{ "ain.unknown.invokeData", PI_MALFORMED, PI_WARN, "Unknown invokeData", EXPFILL } },
        { &ei_ain_unknown_returnResultData,{ "ain.unknown.returnResultData", PI_MALFORMED, PI_WARN, "Unknown returnResultData", EXPFILL } },
        { &ei_ain_unknown_returnErrorData,{ "ain.unknown.returnErrorData", PI_MALFORMED, PI_WARN, "Unknown returnResultData", EXPFILL } },
    };

    expert_module_t* expert_ain;

    /* Register protocol */
    proto_ain = proto_register_protocol(PNAME, PSNAME, PFNAME);
    ain_handle = register_dissector("ain", dissect_ain, proto_ain);
    /* Register fields and subtrees */
    proto_register_field_array(proto_ain, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_ain = expert_register_protocol(proto_ain);
    expert_register_field_array(expert_ain, ei, array_length(ei));

}

/*
* Editor modelines
*
* Local Variables:
* c-basic-offset: 2
* tab-width: 8
* indent-tabs-mode: nil
* End:
*
* ex: set shiftwidth=2 tabstop=8 expandtab:
* :indentSize=2:tabSize=8:noTabs=true:
*/




