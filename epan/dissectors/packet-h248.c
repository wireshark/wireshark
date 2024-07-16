/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-h248.c                                                              */
/* asn2wrs.py -b -q -L -p h248 -c ./h248.cnf -s ./packet-h248-template -D . -O ../.. h248v3.asn h248v1support.asn */

/* packet-h248.c
 * Routines for H.248/MEGACO packet dissection
 *
 * Ronnie Sahlberg 2004
 *
 * Luis Ontanon 2005 - Context and Transaction Tracing
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/tap.h>
#include <epan/asn1.h>
#include <epan/proto_data.h>
#include <epan/prefs.h>
#include <epan/exported_pdu.h>
#include <epan/address_types.h>
#include "packet-alcap.h"
#include "packet-ber.h"
#include "packet-tpkt.h"
#include "packet-mtp3.h"
#include "packet-h248.h"

#define PNAME  "H.248 MEGACO"
#define PSNAME "H.248"
#define PFNAME "h248"

void proto_register_h248(void);

/* Initialize the protocol and registered fields */
static int proto_h248;
static int hf_248_magic_num;
static int hf_h248_mtpaddress_ni;
static int hf_h248_mtpaddress_pc;
static int hf_h248_pkg_name;
static int hf_248_pkg_param;
static int hf_h248_event_name;
static int hf_h248_signal_name;
static int hf_h248_signal_code;
static int hf_h248_event_code;
static int hf_h248_pkg_bcp_BNCChar_PDU;



static int hf_h248_context_id;
static int hf_h248_term_wild_type;
static int hf_h248_term_wild_level;
static int hf_h248_term_wild_position;

static int hf_h248_no_pkg;
static int hf_h248_no_sig;
static int hf_h248_no_evt;
static int hf_h248_param;

static int hf_h248_serviceChangeReasonStr;
static int hf_h248_transactionId64;
static int hf_h248_context_id64;

/* h248v1 support */
static int hf_h248_auditValueReplyV1;

static int hf_h248_authHeader;                    /* AuthenticationHeader */
static int hf_h248_mess;                          /* Message */
static int hf_h248_secParmIndex;                  /* SecurityParmIndex */
static int hf_h248_seqNum;                        /* SequenceNum */
static int hf_h248_ad;                            /* AuthData */
static int hf_h248_version;                       /* T_version */
static int hf_h248_mId;                           /* MId */
static int hf_h248_messageBody;                   /* T_messageBody */
static int hf_h248_messageError;                  /* ErrorDescriptor */
static int hf_h248_transactions;                  /* SEQUENCE_OF_Transaction */
static int hf_h248_transactions_item;             /* Transaction */
static int hf_h248_ip4Address;                    /* IP4Address */
static int hf_h248_ip6Address;                    /* IP6Address */
static int hf_h248_domainName;                    /* DomainName */
static int hf_h248_deviceName;                    /* PathName */
static int hf_h248_mtpAddress;                    /* MtpAddress */
static int hf_h248_domName;                       /* IA5String */
static int hf_h248_portNumber;                    /* INTEGER_0_65535 */
static int hf_h248_iP4Address;                    /* OCTET_STRING_SIZE_4 */
static int hf_h248_iP6Address;                    /* OCTET_STRING_SIZE_16 */
static int hf_h248_transactionRequest;            /* TransactionRequest */
static int hf_h248_transactionPending;            /* TransactionPending */
static int hf_h248_transactionReply;              /* TransactionReply */
static int hf_h248_transactionResponseAck;        /* TransactionResponseAck */
static int hf_h248_segmentReply;                  /* SegmentReply */
static int hf_h248_transactionId;                 /* T_transactionId */
static int hf_h248_actions;                       /* SEQUENCE_OF_ActionRequest */
static int hf_h248_actions_item;                  /* ActionRequest */
static int hf_h248_tpend_transactionId;           /* T_tpend_transactionId */
static int hf_h248_trep_transactionId;            /* T_trep_transactionId */
static int hf_h248_immAckRequired;                /* NULL */
static int hf_h248_transactionResult;             /* T_transactionResult */
static int hf_h248_transactionError;              /* ErrorDescriptor */
static int hf_h248_actionReplies;                 /* SEQUENCE_OF_ActionReply */
static int hf_h248_actionReplies_item;            /* ActionReply */
static int hf_h248_segmentNumber;                 /* SegmentNumber */
static int hf_h248_segmentationComplete;          /* NULL */
static int hf_h248_seg_rep_transactionId;         /* T_seg_rep_transactionId */
static int hf_h248_TransactionResponseAck_item;   /* TransactionAck */
static int hf_h248_firstAck;                      /* TransactionId */
static int hf_h248_lastAck;                       /* TransactionId */
static int hf_h248_errorCode;                     /* T_errorCode */
static int hf_h248_errorText;                     /* ErrorText */
static int hf_h248_contextId;                     /* ContextId */
static int hf_h248_contextRequest;                /* ContextRequest */
static int hf_h248_contextAttrAuditReq;           /* T_contextAttrAuditReq */
static int hf_h248_commandRequests;               /* SEQUENCE_OF_CommandRequest */
static int hf_h248_commandRequests_item;          /* CommandRequest */
static int hf_h248_errorDescriptor;               /* ErrorDescriptor */
static int hf_h248_contextReply;                  /* ContextRequest */
static int hf_h248_commandReply;                  /* SEQUENCE_OF_CommandReply */
static int hf_h248_commandReply_item;             /* CommandReply */
static int hf_h248_priority;                      /* INTEGER_0_15 */
static int hf_h248_emergency;                     /* BOOLEAN */
static int hf_h248_topologyReq;                   /* T_topologyReq */
static int hf_h248_topologyReq_item;              /* TopologyRequest */
static int hf_h248_iepscallind_BOOL;              /* Iepscallind_BOOL */
static int hf_h248_contextProp;                   /* SEQUENCE_OF_PropertyParm */
static int hf_h248_contextProp_item;              /* PropertyParm */
static int hf_h248_contextList;                   /* SEQUENCE_OF_ContextIDinList */
static int hf_h248_contextList_item;              /* ContextIDinList */
static int hf_h248_topology;                      /* NULL */
static int hf_h248_cAAREmergency;                 /* NULL */
static int hf_h248_cAARPriority;                  /* NULL */
static int hf_h248_iepscallind;                   /* NULL */
static int hf_h248_contextPropAud;                /* SEQUENCE_OF_IndAudPropertyParm */
static int hf_h248_contextPropAud_item;           /* IndAudPropertyParm */
static int hf_h248_selectpriority;                /* INTEGER_0_15 */
static int hf_h248_selectemergency;               /* BOOLEAN */
static int hf_h248_selectiepscallind;             /* BOOLEAN */
static int hf_h248_selectLogic;                   /* SelectLogic */
static int hf_h248_andAUDITSelect;                /* NULL */
static int hf_h248_orAUDITSelect;                 /* NULL */
static int hf_h248_command;                       /* Command */
static int hf_h248_optional;                      /* NULL */
static int hf_h248_wildcardReturn;                /* NULL */
static int hf_h248_addReq;                        /* T_addReq */
static int hf_h248_moveReq;                       /* T_moveReq */
static int hf_h248_modReq;                        /* T_modReq */
static int hf_h248_subtractReq;                   /* T_subtractReq */
static int hf_h248_auditCapRequest;               /* T_auditCapRequest */
static int hf_h248_auditValueRequest;             /* T_auditValueRequest */
static int hf_h248_notifyReq;                     /* T_notifyReq */
static int hf_h248_serviceChangeReq;              /* ServiceChangeRequest */
static int hf_h248_addReply;                      /* T_addReply */
static int hf_h248_moveReply;                     /* T_moveReply */
static int hf_h248_modReply;                      /* T_modReply */
static int hf_h248_subtractReply;                 /* T_subtractReply */
static int hf_h248_auditCapReply;                 /* T_auditCapReply */
static int hf_h248_auditValueReply;               /* T_auditValueReply */
static int hf_h248_notifyReply;                   /* T_notifyReply */
static int hf_h248_serviceChangeReply;            /* ServiceChangeReply */
static int hf_h248_terminationFrom;               /* TerminationID */
static int hf_h248_terminationTo;                 /* TerminationID */
static int hf_h248_topologyDirection;             /* T_topologyDirection */
static int hf_h248_streamID;                      /* StreamID */
static int hf_h248_topologyDirectionExtension;    /* T_topologyDirectionExtension */
static int hf_h248_terminationIDList;             /* TerminationIDList */
static int hf_h248_descriptors;                   /* SEQUENCE_OF_AmmDescriptor */
static int hf_h248_descriptors_item;              /* AmmDescriptor */
static int hf_h248_mediaDescriptor;               /* MediaDescriptor */
static int hf_h248_modemDescriptor;               /* ModemDescriptor */
static int hf_h248_muxDescriptor;                 /* MuxDescriptor */
static int hf_h248_eventsDescriptor;              /* EventsDescriptor */
static int hf_h248_eventBufferDescriptor;         /* EventBufferDescriptor */
static int hf_h248_signalsDescriptor;             /* SignalsDescriptor */
static int hf_h248_digitMapDescriptor;            /* DigitMapDescriptor */
static int hf_h248_auditDescriptor;               /* AuditDescriptor */
static int hf_h248_aDstatisticsDescriptor;        /* StatisticsDescriptor */
static int hf_h248_terminationAudit;              /* TerminationAudit */
static int hf_h248_terminationID;                 /* TerminationID */
static int hf_h248_contextAuditResult;            /* TerminationIDList */
static int hf_h248_error;                         /* ErrorDescriptor */
static int hf_h248_auditResult;                   /* AuditResult */
static int hf_h248_auditResultTermList;           /* TermListAuditResult */
static int hf_h248_terminationAuditResult;        /* TerminationAudit */
static int hf_h248_TerminationAudit_item;         /* AuditReturnParameter */
static int hf_h248_observedEventsDescriptor;      /* ObservedEventsDescriptor */
static int hf_h248_aRPstatisticsDescriptor;       /* StatisticsDescriptor */
static int hf_h248_packagesDescriptor;            /* PackagesDescriptor */
static int hf_h248_emptyDescriptors;              /* AuditDescriptor */
static int hf_h248_auditToken;                    /* T_auditToken */
static int hf_h248_auditPropertyToken;            /* SEQUENCE_OF_IndAuditParameter */
static int hf_h248_auditPropertyToken_item;       /* IndAuditParameter */
static int hf_h248_indaudmediaDescriptor;         /* IndAudMediaDescriptor */
static int hf_h248_indaudeventsDescriptor;        /* IndAudEventsDescriptor */
static int hf_h248_indaudeventBufferDescriptor;   /* IndAudEventBufferDescriptor */
static int hf_h248_indaudsignalsDescriptor;       /* IndAudSignalsDescriptor */
static int hf_h248_indauddigitMapDescriptor;      /* IndAudDigitMapDescriptor */
static int hf_h248_indaudstatisticsDescriptor;    /* IndAudStatisticsDescriptor */
static int hf_h248_indaudpackagesDescriptor;      /* IndAudPackagesDescriptor */
static int hf_h248_indAudTerminationStateDescriptor;  /* IndAudTerminationStateDescriptor */
static int hf_h248_indAudMediaDescriptorStreams;  /* IndAudMediaDescriptorStreams */
static int hf_h248_oneStream;                     /* IndAudStreamParms */
static int hf_h248_multiStream;                   /* SEQUENCE_OF_IndAudStreamDescriptor */
static int hf_h248_multiStream_item;              /* IndAudStreamDescriptor */
static int hf_h248_indAudStreamParms;             /* IndAudStreamParms */
static int hf_h248_iASPLocalControlDescriptor;    /* IndAudLocalControlDescriptor */
static int hf_h248_iASPLocalDescriptor;           /* IndAudLocalRemoteDescriptor */
static int hf_h248_iASPRemoteDescriptor;          /* IndAudLocalRemoteDescriptor */
static int hf_h248_statisticsDescriptor;          /* IndAudStatisticsDescriptor */
static int hf_h248_iALCDStreamMode;               /* NULL */
static int hf_h248_iALCDReserveValue;             /* NULL */
static int hf_h248_iALCDReserveGroup;             /* NULL */
static int hf_h248_indAudPropertyParms;           /* SEQUENCE_OF_IndAudPropertyParm */
static int hf_h248_indAudPropertyParms_item;      /* IndAudPropertyParm */
static int hf_h248_streamModeSel;                 /* StreamMode */
static int hf_h248_name;                          /* PkgdName */
static int hf_h248_propertyParms;                 /* PropertyParm */
static int hf_h248_propGroupID;                   /* INTEGER_0_65535 */
static int hf_h248_iAPropertyGroup;               /* IndAudPropertyGroup */
static int hf_h248_IndAudPropertyGroup_item;      /* IndAudPropertyParm */
static int hf_h248_eventBufferControl;            /* NULL */
static int hf_h248_iATSDServiceState;             /* NULL */
static int hf_h248_serviceStateSel;               /* ServiceState */
static int hf_h248_requestID;                     /* RequestID */
static int hf_h248_iAEDPkgdName;                  /* PkgdName */
static int hf_h248_iAEBDEventName;                /* PkgdName */
static int hf_h248_indAudSignal;                  /* IndAudSignal */
static int hf_h248_indAudSeqSigList;              /* IndAudSeqSigList */
static int hf_h248_id;                            /* INTEGER_0_65535 */
static int hf_h248_iASignalList;                  /* IndAudSignal */
static int hf_h248_iASignalName;                  /* PkgdName */
static int hf_h248_signalRequestID;               /* RequestID */
static int hf_h248_digitMapName;                  /* DigitMapName */
static int hf_h248_iAStatName;                    /* PkgdName */
static int hf_h248_packageName;                   /* Name */
static int hf_h248_packageVersion;                /* INTEGER_0_99 */
static int hf_h248_requestId;                     /* RequestID */
static int hf_h248_observedEventLst;              /* SEQUENCE_OF_ObservedEvent */
static int hf_h248_observedEventLst_item;         /* ObservedEvent */
static int hf_h248_eventName;                     /* EventName */
static int hf_h248_eventParList;                  /* SEQUENCE_OF_EventParameter */
static int hf_h248_eventParList_item;             /* EventParameter */
static int hf_h248_timeNotation;                  /* TimeNotation */
static int hf_h248_eventParameterName;            /* EventParameterName */
static int hf_h248_eventParamValue;               /* EventParamValues */
static int hf_h248_eventPar_extraInfo;            /* EventPar_extraInfo */
static int hf_h248_relation;                      /* Relation */
static int hf_h248_range;                         /* BOOLEAN */
static int hf_h248_sublist;                       /* BOOLEAN */
static int hf_h248_EventParamValues_item;         /* EventParamValue */
static int hf_h248_serviceChangeParms;            /* ServiceChangeParm */
static int hf_h248_serviceChangeResult;           /* ServiceChangeResult */
static int hf_h248_serviceChangeResParms;         /* ServiceChangeResParm */
static int hf_h248_wildcard;                      /* SEQUENCE_OF_WildcardField */
static int hf_h248_wildcard_item;                 /* WildcardField */
static int hf_h248_terminationId;                 /* T_terminationId */
static int hf_h248_TerminationIDList_item;        /* TerminationID */
static int hf_h248_termStateDescr;                /* TerminationStateDescriptor */
static int hf_h248_streams;                       /* T_streams */
static int hf_h248_mediaDescriptorOneStream;      /* StreamParms */
static int hf_h248_mediaDescriptorMultiStream;    /* SEQUENCE_OF_StreamDescriptor */
static int hf_h248_mediaDescriptorMultiStream_item;  /* StreamDescriptor */
static int hf_h248_streamParms;                   /* StreamParms */
static int hf_h248_localControlDescriptor;        /* LocalControlDescriptor */
static int hf_h248_localDescriptor;               /* LocalRemoteDescriptor */
static int hf_h248_remoteDescriptor;              /* LocalRemoteDescriptor */
static int hf_h248_sPstatisticsDescriptor;        /* StatisticsDescriptor */
static int hf_h248_streamMode;                    /* StreamMode */
static int hf_h248_reserveValue;                  /* BOOLEAN */
static int hf_h248_reserveGroup;                  /* BOOLEAN */
static int hf_h248_lCDpropertyParms;              /* SEQUENCE_OF_PropertyParm */
static int hf_h248_lCDpropertyParms_item;         /* PropertyParm */
static int hf_h248_propertyName;                  /* PropertyName */
static int hf_h248_propertyParamValue;            /* SEQUENCE_OF_PropertyID */
static int hf_h248_propertyParamValue_item;       /* PropertyID */
static int hf_h248_propParm_extraInfo;            /* PropParm_extraInfo */
static int hf_h248_propGrps;                      /* SEQUENCE_OF_PropertyGroup */
static int hf_h248_propGrps_item;                 /* PropertyGroup */
static int hf_h248_PropertyGroup_item;            /* PropertyParm */
static int hf_h248_tSDpropertyParms;              /* SEQUENCE_OF_PropertyParm */
static int hf_h248_tSDpropertyParms_item;         /* PropertyParm */
static int hf_h248_tSEventBufferControl;          /* EventBufferControl */
static int hf_h248_serviceState;                  /* ServiceState */
static int hf_h248_muxType;                       /* MuxType */
static int hf_h248_termList;                      /* SEQUENCE_OF_TerminationID */
static int hf_h248_termList_item;                 /* TerminationID */
static int hf_h248_nonStandardData;               /* NonStandardData */
static int hf_h248_eventList;                     /* SEQUENCE_OF_RequestedEvent */
static int hf_h248_eventList_item;                /* RequestedEvent */
static int hf_h248_eventAction;                   /* RequestedActions */
static int hf_h248_evParList;                     /* SEQUENCE_OF_EventParameter */
static int hf_h248_evParList_item;                /* EventParameter */
static int hf_h248_secondEvent;                   /* SecondEventsDescriptor */
static int hf_h248_notifyImmediate;               /* NULL */
static int hf_h248_notifyRegulated;               /* RegulatedEmbeddedDescriptor */
static int hf_h248_neverNotify;                   /* NULL */
static int hf_h248_keepActive;                    /* BOOLEAN */
static int hf_h248_eventDM;                       /* EventDM */
static int hf_h248_notifyBehaviour;               /* NotifyBehaviour */
static int hf_h248_resetEventsDescriptor;         /* NULL */
static int hf_h248_digitMapValue;                 /* DigitMapValue */
static int hf_h248_secondaryEventList;            /* SEQUENCE_OF_SecondRequestedEvent */
static int hf_h248_secondaryEventList_item;       /* SecondRequestedEvent */
static int hf_h248_pkgdName;                      /* PkgdName */
static int hf_h248_secondaryEventAction;          /* SecondRequestedActions */
static int hf_h248_EventBufferDescriptor_item;    /* EventSpec */
static int hf_h248_SignalsDescriptor_item;        /* SignalRequest */
static int hf_h248_signal;                        /* Signal */
static int hf_h248_seqSigList;                    /* SeqSigList */
static int hf_h248_signalList;                    /* SEQUENCE_OF_Signal */
static int hf_h248_signalList_item;               /* Signal */
static int hf_h248_signalName;                    /* SignalName */
static int hf_h248_sigType;                       /* SignalType */
static int hf_h248_duration;                      /* INTEGER_0_65535 */
static int hf_h248_notifyCompletion;              /* NotifyCompletion */
static int hf_h248_sigParList;                    /* SEQUENCE_OF_SigParameter */
static int hf_h248_sigParList_item;               /* SigParameter */
static int hf_h248_direction;                     /* SignalDirection */
static int hf_h248_intersigDelay;                 /* INTEGER_0_65535 */
static int hf_h248_sigParameterName;              /* SigParameterName */
static int hf_h248_value;                         /* SigParamValues */
static int hf_h248_extraInfo;                     /* T_extraInfo */
static int hf_h248_SigParamValues_item;           /* SigParamValue */
static int hf_h248_mtl;                           /* SEQUENCE_OF_ModemType */
static int hf_h248_mtl_item;                      /* ModemType */
static int hf_h248_mpl;                           /* SEQUENCE_OF_PropertyParm */
static int hf_h248_mpl_item;                      /* PropertyParm */
static int hf_h248_startTimer;                    /* INTEGER_0_99 */
static int hf_h248_shortTimer;                    /* INTEGER_0_99 */
static int hf_h248_longTimer;                     /* INTEGER_0_99 */
static int hf_h248_digitMapBody;                  /* IA5String */
static int hf_h248_durationTimer;                 /* INTEGER_0_99 */
static int hf_h248_serviceChangeMethod;           /* ServiceChangeMethod */
static int hf_h248_serviceChangeAddress;          /* ServiceChangeAddress */
static int hf_h248_serviceChangeVersion;          /* INTEGER_0_99 */
static int hf_h248_serviceChangeProfile;          /* ServiceChangeProfile */
static int hf_h248_serviceChangeReason;           /* SCreasonValue */
static int hf_h248_serviceChangeDelay;            /* INTEGER_0_4294967295 */
static int hf_h248_serviceChangeMgcId;            /* MId */
static int hf_h248_timeStamp;                     /* TimeNotation */
static int hf_h248_serviceChangeInfo;             /* AuditDescriptor */
static int hf_h248_serviceChangeIncompleteFlag;   /* NULL */
static int hf_h248_SCreasonValue_item;            /* SCreasonValueOctetStr */
static int hf_h248_timestamp;                     /* TimeNotation */
static int hf_h248_profileName;                   /* IA5String_SIZE_1_67 */
static int hf_h248_PackagesDescriptor_item;       /* PackagesItem */
static int hf_h248_StatisticsDescriptor_item;     /* StatisticsParameter */
static int hf_h248_statName;                      /* StatName */
static int hf_h248_statValue;                     /* StatValue */
static int hf_h248_nonStandardIdentifier;         /* NonStandardIdentifier */
static int hf_h248_data;                          /* OCTET_STRING */
static int hf_h248_object;                        /* OBJECT_IDENTIFIER */
static int hf_h248_h221NonStandard;               /* H221NonStandard */
static int hf_h248_experimental;                  /* IA5String_SIZE_8 */
static int hf_h248_t35CountryCode1;               /* INTEGER_0_255 */
static int hf_h248_t35CountryCode2;               /* INTEGER_0_255 */
static int hf_h248_t35Extension;                  /* INTEGER_0_255 */
static int hf_h248_manufacturerCode;              /* INTEGER_0_65535 */
static int hf_h248_date;                          /* IA5String_SIZE_8 */
static int hf_h248_time;                          /* IA5String_SIZE_8 */
static int hf_h248_Value_item;                    /* OCTET_STRING */
static int hf_h248_audit_result;                  /* AuditResultV1 */
static int hf_h248_contectAuditResult;            /* TerminationID */
static int hf_h248_eventParamterName;             /* EventParameterName */
static int hf_h248_event_param_value;             /* EventParamValueV1 */
static int hf_h248_sig_param_value;               /* SigParamValueV1 */
/* named bits */
static int hf_h248_T_auditToken_muxToken;
static int hf_h248_T_auditToken_modemToken;
static int hf_h248_T_auditToken_mediaToken;
static int hf_h248_T_auditToken_eventsToken;
static int hf_h248_T_auditToken_signalsToken;
static int hf_h248_T_auditToken_digitMapToken;
static int hf_h248_T_auditToken_statsToken;
static int hf_h248_T_auditToken_observedEventsToken;
static int hf_h248_T_auditToken_packagesToken;
static int hf_h248_T_auditToken_eventBufferToken;
static int hf_h248_NotifyCompletion_onTimeOut;
static int hf_h248_NotifyCompletion_onInterruptByEvent;
static int hf_h248_NotifyCompletion_onInterruptByNewSignalDescr;
static int hf_h248_NotifyCompletion_otherReason;
static int hf_h248_NotifyCompletion_onIteration;

/* Initialize the subtree pointers */
static int ett_h248;
static int ett_mtpaddress;
static int ett_packagename;
static int ett_codec;
static int ett_wildcard;

static int ett_h248_no_pkg;
static int ett_h248_no_sig;
static int ett_h248_no_evt;

static int h248_tap;

static gcp_hf_ett_t h248_arrel;

static int exported_pdu_tap = -1;


static int ett_h248_MegacoMessage;
static int ett_h248_AuthenticationHeader;
static int ett_h248_Message;
static int ett_h248_T_messageBody;
static int ett_h248_SEQUENCE_OF_Transaction;
static int ett_h248_MId;
static int ett_h248_DomainName;
static int ett_h248_IP4Address;
static int ett_h248_IP6Address;
static int ett_h248_Transaction;
static int ett_h248_TransactionRequest;
static int ett_h248_SEQUENCE_OF_ActionRequest;
static int ett_h248_TransactionPending;
static int ett_h248_TransactionReply;
static int ett_h248_T_transactionResult;
static int ett_h248_SEQUENCE_OF_ActionReply;
static int ett_h248_SegmentReply;
static int ett_h248_TransactionResponseAck;
static int ett_h248_TransactionAck;
static int ett_h248_ErrorDescriptor;
static int ett_h248_ActionRequest;
static int ett_h248_SEQUENCE_OF_CommandRequest;
static int ett_h248_ActionReply;
static int ett_h248_SEQUENCE_OF_CommandReply;
static int ett_h248_ContextRequest;
static int ett_h248_T_topologyReq;
static int ett_h248_SEQUENCE_OF_PropertyParm;
static int ett_h248_SEQUENCE_OF_ContextIDinList;
static int ett_h248_ContextAttrAuditRequest;
static int ett_h248_SEQUENCE_OF_IndAudPropertyParm;
static int ett_h248_SelectLogic;
static int ett_h248_CommandRequest;
static int ett_h248_Command;
static int ett_h248_CommandReply;
static int ett_h248_TopologyRequest;
static int ett_h248_AmmRequest;
static int ett_h248_SEQUENCE_OF_AmmDescriptor;
static int ett_h248_AmmDescriptor;
static int ett_h248_AmmsReply;
static int ett_h248_SubtractRequest;
static int ett_h248_AuditRequest;
static int ett_h248_AuditReply;
static int ett_h248_AuditResult;
static int ett_h248_TermListAuditResult;
static int ett_h248_TerminationAudit;
static int ett_h248_AuditReturnParameter;
static int ett_h248_AuditDescriptor;
static int ett_h248_T_auditToken;
static int ett_h248_SEQUENCE_OF_IndAuditParameter;
static int ett_h248_IndAuditParameter;
static int ett_h248_IndAudMediaDescriptor;
static int ett_h248_IndAudMediaDescriptorStreams;
static int ett_h248_SEQUENCE_OF_IndAudStreamDescriptor;
static int ett_h248_IndAudStreamDescriptor;
static int ett_h248_IndAudStreamParms;
static int ett_h248_IndAudLocalControlDescriptor;
static int ett_h248_IndAudPropertyParm;
static int ett_h248_IndAudLocalRemoteDescriptor;
static int ett_h248_IndAudPropertyGroup;
static int ett_h248_IndAudTerminationStateDescriptor;
static int ett_h248_IndAudEventsDescriptor;
static int ett_h248_IndAudEventBufferDescriptor;
static int ett_h248_IndAudSignalsDescriptor;
static int ett_h248_IndAudSeqSigList;
static int ett_h248_IndAudSignal;
static int ett_h248_IndAudDigitMapDescriptor;
static int ett_h248_IndAudStatisticsDescriptor;
static int ett_h248_IndAudPackagesDescriptor;
static int ett_h248_NotifyRequest;
static int ett_h248_NotifyReply;
static int ett_h248_ObservedEventsDescriptor;
static int ett_h248_SEQUENCE_OF_ObservedEvent;
static int ett_h248_ObservedEvent;
static int ett_h248_SEQUENCE_OF_EventParameter;
static int ett_h248_EventParameter;
static int ett_h248_EventPar_extraInfo;
static int ett_h248_EventParamValues;
static int ett_h248_ServiceChangeRequest;
static int ett_h248_ServiceChangeReply;
static int ett_h248_ServiceChangeResult;
static int ett_h248_TerminationID;
static int ett_h248_SEQUENCE_OF_WildcardField;
static int ett_h248_TerminationIDList;
static int ett_h248_MediaDescriptor;
static int ett_h248_T_streams;
static int ett_h248_SEQUENCE_OF_StreamDescriptor;
static int ett_h248_StreamDescriptor;
static int ett_h248_StreamParms;
static int ett_h248_LocalControlDescriptor;
static int ett_h248_PropertyParm;
static int ett_h248_SEQUENCE_OF_PropertyID;
static int ett_h248_PropParm_extraInfo;
static int ett_h248_LocalRemoteDescriptor;
static int ett_h248_SEQUENCE_OF_PropertyGroup;
static int ett_h248_PropertyGroup;
static int ett_h248_TerminationStateDescriptor;
static int ett_h248_MuxDescriptor;
static int ett_h248_SEQUENCE_OF_TerminationID;
static int ett_h248_EventsDescriptor;
static int ett_h248_SEQUENCE_OF_RequestedEvent;
static int ett_h248_RequestedEvent;
static int ett_h248_RegulatedEmbeddedDescriptor;
static int ett_h248_NotifyBehaviour;
static int ett_h248_RequestedActions;
static int ett_h248_EventDM;
static int ett_h248_SecondEventsDescriptor;
static int ett_h248_SEQUENCE_OF_SecondRequestedEvent;
static int ett_h248_SecondRequestedEvent;
static int ett_h248_SecondRequestedActions;
static int ett_h248_EventBufferDescriptor;
static int ett_h248_EventSpec;
static int ett_h248_SignalsDescriptor;
static int ett_h248_SignalRequest;
static int ett_h248_SeqSigList;
static int ett_h248_SEQUENCE_OF_Signal;
static int ett_h248_Signal;
static int ett_h248_SEQUENCE_OF_SigParameter;
static int ett_h248_NotifyCompletion;
static int ett_h248_SigParameter;
static int ett_h248_T_extraInfo;
static int ett_h248_SigParamValues;
static int ett_h248_ModemDescriptor;
static int ett_h248_SEQUENCE_OF_ModemType;
static int ett_h248_DigitMapDescriptor;
static int ett_h248_DigitMapValue;
static int ett_h248_ServiceChangeParm;
static int ett_h248_SCreasonValue;
static int ett_h248_ServiceChangeAddress;
static int ett_h248_ServiceChangeResParm;
static int ett_h248_ServiceChangeProfile;
static int ett_h248_PackagesDescriptor;
static int ett_h248_PackagesItem;
static int ett_h248_StatisticsDescriptor;
static int ett_h248_StatisticsParameter;
static int ett_h248_NonStandardData;
static int ett_h248_NonStandardIdentifier;
static int ett_h248_H221NonStandard;
static int ett_h248_TimeNotation;
static int ett_h248_Value;
static int ett_h248_AuditReplyV1;
static int ett_h248_AuditResultV1;
static int ett_h248_EventParameterV1;
static int ett_h248_SigParameterV1;

static expert_field ei_h248_errored_command;
static expert_field ei_h248_transactionId64;
static expert_field ei_h248_context_id64;
static expert_field ei_h248_octet_string_expected;

static dissector_table_t subdissector_table;

static int ss7pc_address_type = -1;

/* Gateway Control Protocol -- Context Tracking */

const value_string gcp_cmd_type[] = {
    { GCP_CMD_NONE,               "NoCommand"},
    { GCP_CMD_ADD_REQ,            "addReq"},
    { GCP_CMD_MOVE_REQ,           "moveReq"},
    { GCP_CMD_MOD_REQ,            "modReq"},
    { GCP_CMD_SUB_REQ,            "subtractReq"},
    { GCP_CMD_AUDITCAP_REQ,       "auditCapRequest"},
    { GCP_CMD_AUDITVAL_REQ,       "auditValueRequest"},
    { GCP_CMD_NOTIFY_REQ,         "notifyReq"},
    { GCP_CMD_SVCCHG_REQ,         "serviceChangeReq"},
    { GCP_CMD_TOPOLOGY_REQ,       "topologyReq"},
    { GCP_CMD_CTX_ATTR_AUDIT_REQ, "ctxAttrAuditReq"},
    { GCP_CMD_ADD_REPLY,          "addReply"},
    { GCP_CMD_MOVE_REPLY,         "moveReply"},
    { GCP_CMD_MOD_REPLY,          "modReply"},
    { GCP_CMD_SUB_REPLY,          "subtractReply"},
    { GCP_CMD_AUDITCAP_REPLY,     "auditCapReply"},
    { GCP_CMD_AUDITVAL_REPLY,     "auditValReply"},
    { GCP_CMD_NOTIFY_REPLY,       "notifyReply"},
    { GCP_CMD_SVCCHG_REPLY,       "serviceChangeReply"},
    { GCP_CMD_TOPOLOGY_REPLY,     "topologyReply"},
    { 0, NULL }
};

const value_string gcp_term_types[] = {
    { GCP_TERM_TYPE_AAL1,        "aal1" },
    { GCP_TERM_TYPE_AAL2,        "aal2" },
    { GCP_TERM_TYPE_AAL1_STRUCT, "aal1struct" },
    { GCP_TERM_TYPE_IP_RTP,      "ipRtp" },
    { GCP_TERM_TYPE_TDM,         "tdm" },
    { 0, NULL }
};

static wmem_tree_t* gcp_msgs;
static wmem_tree_t* gcp_trxs;
static wmem_tree_t* gcp_ctxs_by_trx;
static wmem_tree_t* gcp_ctxs;

gcp_msg_t* gcp_msg(packet_info* pinfo, int o, bool keep_persistent_data) {
    gcp_msg_t* m;
    uint32_t framenum = (uint32_t)pinfo->num;
    uint32_t offset = (uint32_t)o;
    address* src = &(pinfo->src);
    address* dst = &(pinfo->dst);
    address* lo_addr;
    address* hi_addr;

    if (keep_persistent_data) {
        wmem_tree_key_t key[3];

        key[0].length = 1;
        key[0].key = &(framenum);
        key[1].length = 1;
        key[1].key = &offset;
        key[2].length = 0;
        key[2].key =NULL;

        if (( m = (gcp_msg_t *)wmem_tree_lookup32_array(gcp_msgs,key) )) {
            m->committed = true;
            return m;
        } else {
            m = wmem_new(wmem_file_scope(), gcp_msg_t);
            m->framenum = framenum;
            m->frametime = pinfo->abs_ts;
            m->trxs = NULL;
            m->committed = false;

            wmem_tree_insert32_array(gcp_msgs,key,m);
        }
    } else {
        m = wmem_new0(pinfo->pool, gcp_msg_t);
        m->framenum = framenum;
        m->trxs = NULL;
        m->committed = false;
    }

    if (cmp_address(src, dst) < 0)  {
        lo_addr = src;
        hi_addr = dst;
    } else {
        lo_addr = dst;
        hi_addr = src;
    }

    switch(lo_addr->type) {
        case AT_NONE:
            m->lo_addr = 0;
            m->hi_addr = 0;
            break;
        case AT_IPv4:
            memcpy((uint8_t*)&(m->hi_addr),hi_addr->data,4);
            memcpy((uint8_t*)&(m->lo_addr),lo_addr->data,4);
            break;
        default:
            if (lo_addr->type == ss7pc_address_type) {
                m->hi_addr = mtp3_pc_hash((const mtp3_addr_pc_t *)hi_addr->data);
                m->lo_addr = mtp3_pc_hash((const mtp3_addr_pc_t *)lo_addr->data);
            }
            else {
                /* XXX: heuristic and error prone */
                m->hi_addr = g_str_hash(address_to_str(pinfo->pool, hi_addr));
                m->lo_addr = g_str_hash(address_to_str(pinfo->pool, lo_addr));
            }
        break;
    }

    return m;
}

gcp_trx_t* gcp_trx(gcp_msg_t* m ,uint32_t t_id , gcp_trx_type_t type, packet_info *pinfo, bool keep_persistent_data) {
    gcp_trx_t* t = NULL;
    gcp_trx_msg_t* trxmsg;

    if ( !m ) return NULL;

    if (keep_persistent_data) {
        if (m->committed) {

            for ( trxmsg = m->trxs; trxmsg; trxmsg = trxmsg->next) {
                if (trxmsg->trx && trxmsg->trx->id == t_id) {
                    return trxmsg->trx;
                }
            }
            DISSECTOR_ASSERT_NOT_REACHED();
        } else {
            wmem_tree_key_t key[4];

            key[0].length = 1;
            key[0].key = &(m->hi_addr);
            key[1].length = 1;
            key[1].key = &(m->lo_addr);
            key[2].length = 1;
            key[2].key = &(t_id);
            key[3].length = 0;
            key[3].key = NULL;

            trxmsg = wmem_new(wmem_file_scope(), gcp_trx_msg_t);
            t = (gcp_trx_t *)wmem_tree_lookup32_array(gcp_trxs,key);

            if (!t) {
                t = wmem_new(wmem_file_scope(), gcp_trx_t);
                t->initial = m;
                t->id = t_id;
                t->type = type;
                t->pendings = 0;
                t->error = 0;
                t->cmds = NULL;

                wmem_tree_insert32_array(gcp_trxs,key,t);
            }

            /* XXX: request, reply and ack + point to frames where they are */
            switch ( type ) {
                case GCP_TRX_PENDING:
                    t->pendings++;
                    break;
                default:
                    break;
            }

        }
    } else {
        t = wmem_new(pinfo->pool, gcp_trx_t);
        trxmsg = wmem_new(pinfo->pool, gcp_trx_msg_t);
        t->initial = NULL;
        t->id = t_id;
        t->type = type;
        t->pendings = 0;
        t->error = 0;
        t->cmds = NULL;
    }

    DISSECTOR_ASSERT(trxmsg);

    trxmsg->trx = t;
    trxmsg->next = NULL;
    trxmsg->last = trxmsg;

    if (m->trxs) {
        m->trxs->last = m->trxs->last->next = trxmsg;
    } else {
        m->trxs = trxmsg;
    }

    return t;
}


gcp_ctx_t* gcp_ctx(gcp_msg_t* m, gcp_trx_t* t, uint32_t c_id, packet_info *pinfo, bool persistent) {
    gcp_ctx_t* context = NULL;
    gcp_ctx_t** context_p = NULL;

    if ( !m || !t ) return NULL;

    if (persistent) {

        wmem_tree_key_t ctx_key[4];
        wmem_tree_key_t trx_key[4];

        ctx_key[0].length = 1;
        ctx_key[0].key = &(m->hi_addr);
        ctx_key[1].length = 1;
        ctx_key[1].key = &(m->lo_addr);
        ctx_key[2].length = 1;
        ctx_key[2].key = &(c_id);
        ctx_key[3].length = 0;
        ctx_key[3].key = NULL;

        trx_key[0].length = 1;
        trx_key[0].key = &(m->hi_addr);
        trx_key[1].length = 1;
        trx_key[1].key = &(m->lo_addr);
        trx_key[2].length = 1;
        trx_key[2].key = &(t->id);
        trx_key[3].length = 0;
        trx_key[3].key = NULL;

        if (m->committed) {
            if (( context = (gcp_ctx_t *)wmem_tree_lookup32_array(gcp_ctxs_by_trx,trx_key) )) {
                return context;
            } if ((context_p = (gcp_ctx_t **)wmem_tree_lookup32_array(gcp_ctxs,ctx_key))) {
                context = *context_p;

                do {
                    if (context->initial->framenum <= m->framenum) {
                        return context;
                    }
                } while(( context = context->prev ));

                DISSECTOR_ASSERT(! "a context should exist");
            }
        } else {
            if (c_id == CHOOSE_CONTEXT) {
                if (! ( context = (gcp_ctx_t *)wmem_tree_lookup32_array(gcp_ctxs_by_trx,trx_key))) {
                    context = wmem_new(wmem_file_scope(), gcp_ctx_t);
                    context->initial = m;
                    context->cmds = NULL;
                    context->id = c_id;
                    context->terms.last = &(context->terms);
                    context->terms.next = NULL;
                    context->terms.term = NULL;

                    wmem_tree_insert32_array(gcp_ctxs_by_trx,trx_key,context);
                }
            } else {
                if (( context = (gcp_ctx_t *)wmem_tree_lookup32_array(gcp_ctxs_by_trx,trx_key) )) {
                    if (( context_p = (gcp_ctx_t **)wmem_tree_lookup32_array(gcp_ctxs,ctx_key) )) {
                        if (context != *context_p) {
                            if(context->id != CHOOSE_CONTEXT) {
                                context = wmem_new(wmem_file_scope(), gcp_ctx_t);
                            }
                            context->initial = m;
                            context->id = c_id;
                            context->cmds = NULL;
                            context->terms.last = &(context->terms);
                            context->terms.next = NULL;
                            context->terms.term = NULL;

                            context->prev = *context_p;
                            *context_p = context;
                        }
                    } else {
                        context_p = wmem_new(wmem_file_scope(), gcp_ctx_t*);
                        *context_p = context;
                        context->initial = m;
                        context->id = c_id;
                        wmem_tree_insert32_array(gcp_ctxs,ctx_key,context_p);
                    }
                } else if (! ( context_p = (gcp_ctx_t**)wmem_tree_lookup32_array(gcp_ctxs,ctx_key) )) {
                    context = wmem_new(wmem_file_scope(), gcp_ctx_t);
                    context->initial = m;
                    context->id = c_id;
                    context->cmds = NULL;
                    context->terms.last = &(context->terms);
                    context->terms.next = NULL;
                    context->terms.term = NULL;

                    context_p = wmem_new(wmem_file_scope(), gcp_ctx_t*);
                    *context_p = context;
                    wmem_tree_insert32_array(gcp_ctxs,ctx_key,context_p);
                } else {
                    context = *context_p;
                }
            }
        }
    } else {
        context = wmem_new(pinfo->pool, gcp_ctx_t);
        context->initial = m;
        context->cmds = NULL;
        context->id = c_id;
        context->terms.last = &(context->terms);
        context->terms.next = NULL;
        context->terms.term = NULL;
    }

    return context;
}

gcp_cmd_t* gcp_cmd(gcp_msg_t* m, gcp_trx_t* t, gcp_ctx_t* c, gcp_cmd_type_t type, unsigned offset, packet_info *pinfo, bool persistent) {
    gcp_cmd_t* cmd;
    gcp_cmd_msg_t* cmdtrx;
    gcp_cmd_msg_t* cmdctx;

    if ( !m || !t || !c ) return NULL;

    if (persistent) {
        if (m->committed) {
            DISSECTOR_ASSERT(t->cmds != NULL);

            for (cmdctx = t->cmds; cmdctx; cmdctx = cmdctx->next) {
                cmd = cmdctx->cmd;
                if (cmd->msg == m && cmd->offset == offset) {
                    return cmd;
                }
            }

            DISSECTOR_ASSERT(!"called for a command that does not exist!");

            return NULL;
        } else {
            cmd = wmem_new(wmem_file_scope(), gcp_cmd_t);
            cmdtrx = wmem_new(wmem_file_scope(), gcp_cmd_msg_t);
            cmdctx = wmem_new(wmem_file_scope(), gcp_cmd_msg_t);
        }
    } else {
        cmd = wmem_new(pinfo->pool, gcp_cmd_t);
        cmdtrx = wmem_new(pinfo->pool, gcp_cmd_msg_t);
        cmdctx = wmem_new(pinfo->pool, gcp_cmd_msg_t);
    }

    cmd->type = type;
    cmd->offset = offset;
    cmd->terms.term = NULL;
    cmd->terms.next = NULL;
    cmd->terms.last = &(cmd->terms);
    cmd->str = NULL;
    cmd->msg = m;
    if ((type != GCP_CMD_NONE) && (!persistent)){
        cmd->str = val_to_str_const(type, gcp_cmd_type, "Unknown");
    }
    cmd->trx = t;
    cmd->ctx = c;
    cmd->error = 0;

    cmdctx->cmd = cmdtrx->cmd = cmd;
    cmdctx->next =  cmdtrx->next = NULL;
    cmdctx->last = cmdtrx->last = NULL;

    if (t->cmds) {
        t->cmds->last->next = cmdtrx;
        t->cmds->last = cmdtrx;
    } else {
        t->cmds = cmdtrx;
        t->cmds->last = cmdtrx;
    }

    if (c->cmds) {
        c->cmds->last->next = cmdctx;
        c->cmds->last = cmdctx;
    } else {
        c->cmds = cmdctx;
        c->cmds->last = cmdctx;
    }

    return cmd;
}

gcp_term_t* gcp_cmd_add_term(gcp_msg_t* m, gcp_trx_t* tr, gcp_cmd_t* c, gcp_term_t* t, gcp_wildcard_t wildcard, packet_info *pinfo, bool persistent) {
    gcp_terms_t* ct;
    gcp_terms_t* ct2;

    static gcp_term_t all_terms = {"$",(const uint8_t*)"",1,GCP_TERM_TYPE_UNKNOWN,NULL,NULL,NULL};

    if ( !c ) return NULL;

    if ( wildcard == GCP_WILDCARD_CHOOSE) {
        return &all_terms;
    }

    if (persistent) {
        if ( c->msg->committed ) {
            if (wildcard == GCP_WILDCARD_ALL) {
                for (ct = c->ctx->terms.next; ct; ct = ct->next) {
                    /* XXX not handling more wildcards in one msg */
                    if ( ct->term->start == m ) {
                        return ct->term;
                    }
                }
                return NULL;
            } else {
                for (ct = c->ctx->terms.next; ct; ct = ct->next) {
                    if ( g_str_equal(ct->term->str,t->str) ) {
                        return ct->term;
                    }
                }
                return NULL;
            }
        } else {

            for (ct = c->ctx->terms.next; ct; ct = ct->next) {
                if ( g_str_equal(ct->term->str,t->str) || ct->term->start == m) {
                    break;
                }
            }

            if ( ! ct ) {

                if (wildcard == GCP_WILDCARD_ALL) {
                    ct = wmem_new(wmem_file_scope(), gcp_terms_t);
                    ct->next = NULL;
                    ct->term = wmem_new0(wmem_file_scope(), gcp_term_t);

                    ct->term->start = m;
                    ct->term->str = "*";
                    ct->term->buffer = NULL;
                    ct->term->len = 0;

                    c->terms.last = c->terms.last->next = ct;

                    ct2 = wmem_new0(wmem_file_scope(), gcp_terms_t);
                    ct2->term = ct->term;

                    c->ctx->terms.last->next = ct2;
                    c->ctx->terms.last = ct2;

                    return ct->term;
                } else {
                    for (ct = c->ctx->terms.next; ct; ct = ct->next) {
                        /* XXX not handling more wildcards in one msg */
                        if ( ct->term->buffer == NULL && tr->cmds->cmd->msg == ct->term->start ) {
                            ct->term->str = wmem_strdup(wmem_file_scope(), t->str);
                            ct->term->buffer = (const uint8_t *)wmem_memdup(wmem_file_scope(), t->buffer,t->len);
                            ct->term->len = t->len;

                            ct2 = wmem_new0(wmem_file_scope(), gcp_terms_t);
                            ct2->term = ct->term;

                            c->terms.last = c->terms.last->next = ct2;

                            return ct->term;
                        }

                        if  ( g_str_equal(ct->term->str,t->str) ) {
                            ct2 = wmem_new0(wmem_file_scope(), gcp_terms_t);
                            ct2->term = ct->term;

                            c->terms.last = c->terms.last->next = ct2;

                            return ct->term;
                        }
                    }

                    ct = wmem_new(wmem_file_scope(), gcp_terms_t);
                    ct->next = NULL;
                    ct->term = wmem_new0(wmem_file_scope(), gcp_term_t);

                    ct->term->start = m;
                    ct->term->str = wmem_strdup(wmem_file_scope(), t->str);
                    ct->term->buffer = (const uint8_t *)wmem_memdup(wmem_file_scope(), t->buffer,t->len);
                    ct->term->len = t->len;

                    ct2 = wmem_new0(wmem_file_scope(), gcp_terms_t);
                    ct2->term = ct->term;

                    c->terms.last = c->terms.last->next = ct2;

                    ct2 = wmem_new0(wmem_file_scope(), gcp_terms_t);
                    ct2->term = ct->term;

                    c->ctx->terms.last = c->ctx->terms.last->next = ct2;

                    return ct->term;
                }
            } else {
                ct2 = wmem_new0(wmem_file_scope(), gcp_terms_t);
                ct2->term = ct->term;

                c->terms.last = c->terms.last->next = ct2;
                return ct->term;
            }

            DISSECTOR_ASSERT_NOT_REACHED();
        }
    } else {
        ct = wmem_new(pinfo->pool, gcp_terms_t);
        ct->term = t;
        ct->next = NULL;
        c->terms.last = c->terms.last->next = ct;

        return t;
    }

}

static const char* gcp_cmd_to_str(gcp_cmd_t* c, wmem_allocator_t *scope, bool persistent) {
    const char* s;
    gcp_terms_t* term;

    if ( !c ) return "-";

    switch (c->type) {
        case GCP_CMD_NONE:
            return "-";
        case GCP_CMD_ADD_REQ:
            s = "AddReq {";
            break;
        case GCP_CMD_MOVE_REQ:
            s = "MoveReq {";
            break;
        case GCP_CMD_MOD_REQ:
            s = "ModReq {";
            break;
        case GCP_CMD_SUB_REQ:
            s = "SubReq {";
            break;
        case GCP_CMD_AUDITCAP_REQ:
            s = "AuditCapReq {";
            break;
        case GCP_CMD_AUDITVAL_REQ:
            s = "AuditValReq {";
            break;
        case GCP_CMD_NOTIFY_REQ:
            s = "NotifyReq {";
            break;
        case GCP_CMD_SVCCHG_REQ:
            s = "SvcChgReq {";
            break;
        case GCP_CMD_TOPOLOGY_REQ:
            s = "TopologyReq {";
            break;
        case GCP_CMD_CTX_ATTR_AUDIT_REQ:
            s = "CtxAttribAuditReq {";
            break;
        case GCP_CMD_ADD_REPLY:
            s = "AddReply {";
            break;
        case GCP_CMD_MOVE_REPLY:
            s = "MoveReply {";
            break;
        case GCP_CMD_MOD_REPLY:
            s = "ModReply {";
            break;
        case GCP_CMD_SUB_REPLY:
            s = "SubReply {";
            break;
        case GCP_CMD_AUDITCAP_REPLY:
            s = "AuditCapReply {";
            break;
        case GCP_CMD_AUDITVAL_REPLY:
            s = "AuditValReply {";
            break;
        case GCP_CMD_NOTIFY_REPLY:
            s = "NotifyReply {";
            break;
        case GCP_CMD_SVCCHG_REPLY:
            s = "SvcChgReply {";
            break;
        case GCP_CMD_TOPOLOGY_REPLY:
            s = "TopologyReply {";
            break;
        case GCP_CMD_REPLY:
            s = "ActionReply {";
            break;
        case GCP_CMD_OTHER_REQ:
            s = "Request {";
            break;
        default:
            s = "-";
            break;
    }

    for (term = c->terms.next; term; term = term->next) {
        s = wmem_strdup_printf(scope, "%s %s", s, term->term->str);
    }

    if (c->error) {
        s = wmem_strdup_printf(scope, "%s Error=%i", s, c->error);
    }

    s = wmem_strdup_printf(scope, "%s }", s);

    if (persistent) {
        /* FIXME: this method has a side-effect but is buried deep within an apparently side-effect free string helper */
        if (! c->str) c->str = wmem_strdup(wmem_file_scope(), s);
    } else {
        c->str = s;
    }

    return s;
}

static const char * gcp_trx_to_str(gcp_msg_t* m, gcp_trx_t* t, wmem_allocator_t *scope, bool persistent) {
    wmem_strbuf_t *s;
    gcp_cmd_msg_t* c;

    if ( !m || !t ) return "-";

    s = wmem_strbuf_new(scope, NULL);
    wmem_strbuf_append_printf(s, "T %x { ", t->id);

    if (t->cmds) {
        if (t->cmds->cmd->ctx) {
            wmem_strbuf_append_printf(s, " C %x {", t->cmds->cmd->ctx->id);

            for (c = t->cmds; c; c = c->next) {
                if (c->cmd->msg == m) {
                    wmem_strbuf_append_c(s, ' ');
                    wmem_strbuf_append(s, gcp_cmd_to_str(c->cmd, scope, persistent));
                }
            }

            wmem_strbuf_append(s, " }");
        }
    }

    if (t->error) {
        wmem_strbuf_append_printf(s, " Error=%i", t->error);
    }

    wmem_strbuf_append(s, " }");

    return wmem_strbuf_finalize(s);
}

const char* gcp_msg_to_str(gcp_msg_t* m, wmem_allocator_t *scope, bool persistent) {
    gcp_trx_msg_t* t;
    wmem_strbuf_t *s;

    if ( !m ) return "-";

    s = wmem_strbuf_new(scope, NULL);
    for (t = m->trxs; t; t = t->next) {
        wmem_strbuf_append_c(s, ' ');
        wmem_strbuf_append(s, gcp_trx_to_str(m, t->trx, scope, persistent));
    }

    return wmem_strbuf_finalize(s);
}

typedef struct _gcp_ctxs_t {
    struct _gcp_ctx_t* ctx;
    struct _gcp_ctxs_t* next;
} gcp_ctxs_t;

/*static const char* trx_types[] = {"None","Req","Reply","Pending","Ack"};*/

void gcp_analyze_msg(proto_tree* gcp_tree, packet_info* pinfo, tvbuff_t* gcp_tvb, gcp_msg_t* m, gcp_hf_ett_t* ids, expert_field* command_err) {
    gcp_trx_msg_t* t;
    gcp_ctxs_t contexts = {NULL,NULL};
    gcp_ctxs_t* ctx_node;
    gcp_cmd_msg_t* c;


    for (t = m->trxs; t; t = t->next) {
        for (c = t->trx->cmds; c; c = c->next) {
            gcp_ctx_t* ctx = c->cmd->ctx;

            for (ctx_node = contexts.next; ctx_node; ctx_node = ctx_node->next) {
                if (ctx_node->ctx->id == ctx->id) {
                    break;
                }
            }

            if (! ctx_node) {
                ctx_node = wmem_new(pinfo->pool, gcp_ctxs_t);
                ctx_node->ctx = ctx;
                ctx_node->next = contexts.next;
                contexts.next = ctx_node;
            }
        }
    }

    for (ctx_node = contexts.next; ctx_node; ctx_node = ctx_node->next) {
        gcp_ctx_t* ctx = ctx_node->ctx;
        proto_item* ctx_item = proto_tree_add_uint(gcp_tree,ids->hf.ctx,gcp_tvb,0,0,ctx->id);
        proto_tree* ctx_tree = proto_item_add_subtree(ctx_item,ids->ett.ctx);
        gcp_terms_t *ctx_term;

        proto_item_set_generated(ctx_item);

        if (ctx->cmds) {
            proto_tree* history_tree = proto_tree_add_subtree(ctx_tree,gcp_tvb,0,0,ids->ett.ctx_cmds,NULL,"[ Command History ]");

            for (c = ctx->cmds; c; c = c->next) {
                proto_item* cmd_item = proto_tree_add_uint(history_tree,ids->hf.ctx_cmd,gcp_tvb,0,0,c->cmd->msg->framenum);
                if (c->cmd->str) proto_item_append_text(cmd_item,"  %s ",c->cmd->str);
                proto_item_set_generated(cmd_item);
                if (c->cmd->error) {
                    expert_add_info(pinfo, cmd_item, command_err);
                }
            }
        }

        if (( ctx_term = ctx->terms.next )) {
            proto_tree* terms_tree = proto_tree_add_subtree(ctx_tree,gcp_tvb,0,0,ids->ett.ctx_terms,NULL,"[ Terminations Used ]");

            for (; ctx_term; ctx_term = ctx_term->next ) {
                if ( ctx_term->term && ctx_term->term->str) {
                    proto_item* pi = proto_tree_add_string(terms_tree,ids->hf.ctx_term,gcp_tvb,0,0,ctx_term->term->str);
                    proto_tree* term_tree = proto_item_add_subtree(pi,ids->ett.ctx_term);

                    proto_item_set_generated(pi);

                    if (ctx_term->term->type) {
                        pi = proto_tree_add_uint(term_tree,ids->hf.ctx_term_type,gcp_tvb,0,0,ctx_term->term->type);
                        proto_item_set_generated(pi);
                    }

                    if (ctx_term->term->bir) {
                        pi = proto_tree_add_string(term_tree,ids->hf.ctx_term_bir,gcp_tvb,0,0,ctx_term->term->bir);
                        proto_item_set_generated(pi);
                    }

                    if (ctx_term->term->nsap) {
                        pi = proto_tree_add_string(term_tree,ids->hf.ctx_term_nsap,gcp_tvb,0,0,ctx_term->term->nsap);
                        proto_item_set_generated(pi);
                    }

                    if (ctx_term->term->bir && ctx_term->term->nsap) {
                        char* tmp_key = wmem_strdup_printf(pinfo->pool, "%s:%s",ctx_term->term->nsap,ctx_term->term->bir);
                        char* key = g_ascii_strdown(tmp_key, -1);
                        alcap_tree_from_bearer_key(term_tree, gcp_tvb, pinfo, key);
                        g_free(key);
                    }
                }
            }
        }
    }
}

/* END Gateway Control Protocol -- Context Tracking */

#define H248_PORT 2945
static bool keep_persistent_data;
static bool h248_desegment = true;



static proto_tree *h248_tree;

static dissector_handle_t h248_handle;
static dissector_handle_t h248_term_handle;
static dissector_handle_t h248_tpkt_handle;

/* Forward declarations */
static int dissect_h248_ServiceChangeReasonStr(bool implicit_tag, tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);

/* h248v1 support */
static int dissect_h248_AuditReplyV1(bool implicit_tag, tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);

static int dissect_h248_EventParameterV1(bool implicit_tag, tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
static int dissect_h248_SigParameterV1(bool implicit_tag, tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
static int dissect_h248_SigParamValueV1(bool implicit_tag, tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);

#if 0
static const value_string context_id_type[] = {
    {NULL_CONTEXT,"0 (Null Context)"},
    {CHOOSE_CONTEXT,"$ (Choose Context)"},
    {ALL_CONTEXTS,"* (All Contexts)"},
    {0,NULL}
};
#endif

/* the following value_strings are used to build defalut packages.
   To add additional detail to a package, build a register a h248_package_t structure
 */

static const value_string base_package_name_vals[] = {
    {   0x0000, "Media stream properties H.248.1 Annex C" },
    {   0x0001, "Generic H.248.1 Annex E" },
    {   0x0002, "root H.248.1 Annex E" },
    {   0x0003, "tonegen H.248.1 Annex E" },
    {   0x0004, "tonedet H.248.1 Annex E" },
    {   0x0005, "dg H.248.1 Annex E" },
    {   0x0006, "dd H.248.1 Annex E" },
    {   0x0007, "cg H.248.1 Annex E" },
    {   0x0008, "cd H.248.1 Annex E" },
    {   0x0009, "al H.248.1 Annex E" },
    {   0x000a, "ct H.248.1 Annex E" },
    {   0x000b, "nt H.248.1 Annex E" },
    {   0x000c, "rtp H.248.1 Annex E" },
    {   0x000d, "tdmc H.248.1 Annex E" },
    {   0x000e, "ftmd H.248.1 Annex E" },
    {   0x000f, "txc H.248.2" },                                          /* H.248.2 */
    {   0x0010, "txp H.248.2" },
    {   0x0011, "ctyp H.248.2" },
    {   0x0012, "fax H.248.2" },
    {   0x0013, "ipfax H.248.2" },
    {   0x0014, "dis H.248.3" },                                          /* H.248.3 */
    {   0x0015, "key H.248.3" },
    {   0x0016, "kp H.248.3" },
    {   0x0017, "labelkey H.248.3" },
    {   0x0018, "kf H.248.3" },
    {   0x0019, "ind H.248.3" },
    {   0x001a, "ks H.248.3" },
    {   0x001b, "anci H.248.3" },
    {   0x001c, "dtd H.248.6" },                                              /* H.248.6 */
    {   0x001d, "an H.248.7" },                                               /* H.248.7 */
    {   0x001e, "Bearer Characteristics Q.1950 Annex A" },                    /* Q.1950 Annex A */
    {   0x001f, "Bearer Network Connection Cut Q.1950 Annex A" },
    {   0x0020, "Reuse Idle Q.1950 Annex A" },
    {   0x0021, "Generic Bearer Connection Q.1950 Annex A" },
    {   0x0022, "Bearer Control Tunnelling Q.1950 Annex A" },
    {   0x0023, "Basic Call Progress Tones Q.1950 Annex A" },
    {   0x0024, "Expanded Call Progress Tones Q.1950 Annex A" },
    {   0x0025, "Basic Services Tones Q.1950 Annex A" },
    {   0x0026, "Expanded Services Tones Q.1950 Annex A" },
    {   0x0027, "Intrusion Tones Q.1950 Annex A" },
    {   0x0028, "Business Tones Q.1950 Annex A" },
    {   0x0029, "Media Gateway Resource Congestion Handling H.248.10" },      /* H.248.10 */
    {   0x002a, "H245 package H.248.12" },                                    /* H.248.12 */
    {   0x002b, "H323 bearer control package H.248.12" },                     /* H.248.12 */
    {   0x002c, "H324 package H.248.12" },                                    /* H.248.12 */
    {   0x002d, "H245 command package H.248.12" },                            /* H.248.12 */
    {   0x002e, "H245 indication package H.248.12" },                         /* H.248.12 */
    {   0x002f, "3G User Plane" },                                            /* 3GPP TS 29.232 v4.1.0 */
    {   0x0030, "3G Circuit Switched Data" },
    {   0x0031, "3G TFO Control" },
    {   0x0032, "3G Expanded Call Progress Tones" },
    {   0x0033, "Advanced Audio Server (AAS Base)" },                         /* H.248.9 */
    {   0x0034, "AAS Digit Collection" },                                     /* H.248.9 */
    {   0x0035, "AAS Recording" },                                            /* H.248.9 */
    {   0x0036, "AAS Segment Management" },                                   /* H.248.9 */
    {   0x0037, "Quality Alert Ceasing" },                                    /* H.248.13 */
    {   0x0038, "Conferencing Tones Generation" },                            /* H.248.27 */
    {   0x0039, "Diagnostic Tones Generation" },                              /* H.248.27 */
    {   0x003a, "Carrier Tones Generation Package H.248.23" },                /* H.248.27 */
    {   0x003b, "Enhanced Alerting Package H.248.23" },                       /* H.248.23 */
    {   0x003c, "Analog Display Signalling Package H.248.23" },               /* H.248.23 */
    {   0x003d, "Multi-Frequency Tone Generation Package H.248.24" },         /* H.248.24 */
    {   0x003e, "H.248.23Multi-Frequency Tone Detection Package H.248.24" },  /* H.248.24 */
    {   0x003f, "Basic CAS Package H.248.25" },                               /* H.248.25 */
    {   0x0040, "Robbed Bit Signalling Package H.248.25" },                   /* H.248.25 */
    {   0x0041, "Operator Services and Emergency Services Package H.248.25" },
    {   0x0042, "Operator Services Extension Package H.248.25" },
    {   0x0043, "Extended Analog Line Supervision Package H.248.26" },
    {   0x0044, "Automatic Metering Package H.248.26" },
    {   0x0045, "Inactivity Timer Package H.248.14" },
    {   0x0046, "3G Modification of Link Characteristics Bearer Capability" }, /* 3GPP TS 29.232 v4.4.0 */
    {   0x0047, "Base Announcement Syntax H.248.9" },
    {   0x0048, "Voice Variable Syntax H.248.9" },
    {   0x0049, "Announcement Set Syntax H.248.9" },
    {   0x004a, "Phrase Variable Syntax H.248.9" },
    {   0x004b, "Basic NAS package" },
    {   0x004c, "NAS incoming package" },
    {   0x004d, "NAS outgoing package" },
    {   0x004e, "NAS control package" },
    {   0x004f, "NAS root package" },
    {   0x0050, "Profile Handling Package H.248.18" },
    {   0x0051, "Media Gateway Overload Control Package H.248.11" },
    {   0x0052, "Extended DTMF Detection Package H.248.16" },
    {   0x0053, "Quiet Termination Line Test" },
    {   0x0054, "Loopback Line Test Response" },                              /* H.248.17 */
    {   0x0055, "ITU 404Hz Line Test" },                                      /* H.248.17 */
    {   0x0056, "ITU 816Hz Line Test" },                                      /* H.248.17 */
    {   0x0057, "ITU 1020Hz Line Test" },                                     /* H.248.17 */
    {   0x0058, "ITU 2100Hz Disable Tone Line Test" },                        /* H.248.17 */
    {   0x0059, "ITU 2100Hz Disable Echo Canceller Tone Line Test" },         /* H.248.17 */
    {   0x005a, "ITU 2804Hz Tone Line Test" },                                /* H.248.17 */
    {   0x005b, "ITU Noise Test Tone Line Test" },                            /* H.248.17 */
    {   0x005c, "ITU Digital Pseudo Random Test Line Test" },                 /* H.248.17 */
    {   0x005d, "ITU ATME No.2 Test Line Response" },                         /* H.248.17 */
    {   0x005e, "ANSI 1004Hz Test Tone Line Test" },                          /* H.248.17 */
    {   0x005f, "ANSI Test Responder Line Test" },                            /* H.248.17 */
    {   0x0060, "ANSI 2225Hz Test Progress Tone Line Test" },                 /* H.248.17 */
    {   0x0061, "ANSI Digital Test Signal Line Test" },                       /* H.248.17 */
    {   0x0062, "ANSI Inverting Loopback Line Test Response" },               /* H.248.17 */
    {   0x0063, "Extended H.324 Packages H.248.12 Annex A" },
    {   0x0064, "Extended H.245 Command Package H.248.12 Annex A" },
    {   0x0065, "Extended H.245 Indication Package H.248.12 Annex A" },
    {   0x0066, "Enhanced DTMF Detection Package H.248.16" },
    {   0x0067, "Connection Group Identity Package Q.1950 Annex E" },
    {   0x0068, "CTM Text Transport 3GPP TS 29.232 v5.2.0" },
    {   0x0069, "SPNE Control Package Q.115.0" },
    {   0x006a, "Semi-permanent Connection Package H.248.21" },
    {   0x006b, "Shared Risk Group Package H.248.22" },
    {   0x006c, "isuptn Annex B of ITU-T Rec. J.171" },
    {   0x006d, "Basic CAS Addressing Package H.248.25" },
    {   0x006e, "Floor Control Package H.248.19" },
    {   0x006f, "Indication of Being Viewed Package H.248.19" },
    {   0x0070, "Volume Control Package H.248.19" },
    {   0x0071, "UNASSIGNED" },
    {   0x0072, "Volume Detection Package H.248.19" },
    {   0x0073, "Volume Level Mixing Package H.248.19" },
    {   0x0074, "Mixing Volume Level Control Package H.248.19" },
    {   0x0075, "Voice Activated Video Switch Package H.248.19" },
    {   0x0076, "Lecture Video Mode Package H.248.19" },
    {   0x0077, "Contributing Video Source Package H.248.19" },
    {   0x0078, "Video Window Package H.248.19" },
    {   0x0079, "Tiled Window Package H.248.19" },
    {   0x007a, "Adaptive Jitter Buffer Package H.248.31" },
    {   0x007b, "International CAS Package H.248.28" },
    {   0x007c, "CAS Blocking Package H.248.28" },
    {   0x007d, "International CAS Compelled Package H.248.29" },
    {   0x007e, "International CAS Compelled with Overlap Package H.248.29" },
    {   0x007f, "International CAS Compelled with End-to-end Package H.248.29" },
    {   0x0080, "RTCP XR Package H.248.30" },
    {   0x0081, "RTCP XR Burst Metrics Package H.248.30" },
    {   0x0082, "threegcsden 3G Circuit Switched Data" },                     /* 3GPP TS 29.232 v5.6.0 */
    {   0x0083, "threegiptra 3G Circuit Switched Data" },                     /* 3GPP TS 29.232 v5.6.0 */
    {   0x0084, "threegflex 3G Circuit Switched Data" },                      /* 3GPP TS 29.232 v5.6.0 */
    {   0x0085, "H.248 PCMSB" },
    {   0x008a, "TIPHON Extended H.248/MEGACO Package" },                     /* ETSI specification TS 101 3 */
    {   0x008b, "Differentiated Services Package" },                          /* Annex A of ETSI TS 102 333 */
    {   0x008c, "Gate Management Package" },                                  /* Annex B of ETSI TS 102 333 */
    {   0x008d, "Traffic Management Package" },                               /* Annex C of ETSI TS 102 333 */
    {   0x008e, "Gate Recovery Information Package" },                        /* Annex D of ETSI TS 102 333 */
    {   0x008f, "NAT Traversal Package" },                                    /* Annex E of ETSI TS 102 333 */
    {   0x0090, "MPLS Package" },                                             /* Annex F of ETSI TS 102 333 */
    {   0x0091, "VLAN Package" },                                             /* Annex G of ETSI TS 102 333 */
    {   0x0092, "Detailed Congestion Reporting Package" },                    /* H.248.32 */
    {   0x0093, "Stimulus Analogue Lines Package" },                          /* H.248.34 */
    {   0x0094, "icascgen" },                                                 /* H.248.29 Annex B */
    {   0x0095, "Coin Operated Phone Control Package" },                      /* H.248.35 */
    {   0x0096, "Metering Pulse Detection Package" },                         /* H.248.26 Amendment 1 */
    {   0x0097, "Trace Package" },                                            /* 3GPP TS 29.232 v6.3.0 */
    {   0x0098, "Hanging Termination Package" },                              /* H.248.36 */
    {   0x0099, "IP NAPT Traversal Package" },                                /* H.248.37 */
    {   0x009a, "Notification Behaviour Package" },                           /* H.248.1v3 */
    {   0x009b, "Base Context Package" },                                     /* H.248.38 */
    {   0x009c, "Application Data Inactivity Detection Package" },            /* H.248.40 */
    {   0x009d, "Domain Connection Package " },                               /* H.248.41 */
    {   0x009e, "Digital Circuit Multiplication Equipment Package" },         /* H.248.42 */
    {   0x009f, "Multi-level Precedence and Pre-emption Package" },           /* H.248.44 */
    {   0x00a0, "MGC Information Package" },                                  /* H.248.45 */
    {   0x00a1, "Text Overlay Package" },                                     /* H.248.19 Amendment 1 */
    {   0x00a2, "Border and Background Package" },                            /* H.248.19 Amendment 1 */
    {   0x00a3, "Segmentation Package" },                                     /* H.248.1v3 */
    {   0x00a4, "ETSI notification behaviour package" },                      /* ETSI ES 283 039-3 */
    {   0x00a5, "ETSI notification rate package" },                           /* ETSI ES 283 039-4 */
    {   0x00a6, "Automatic Speech Recognition Package" },                     /* H.248.9 Amendment 1 */
    {   0x00a7, "Set extension to basic syntax for TTS enhancement Package" },/* H.248.9 Amendment 1 */
    {   0x00a8, "Advanced audio server base package for TTS enhancement" },   /* H.248.9 Amendment 1 */
    {   0x00a9, "Multimedia Play Package" },                                  /* H.248.9 Amendment 1 */
    {   0x00aa, "Floor Status Detection Package" },                           /* H.248.19 Amendment 2 */
    {   0x00ab, "Floor Control Policy Package" },                             /* H.248.19 Amendment 2 */
    {   0x00ac, "Address Reporting Package" },                                /* H.248.37 Amendment 1 */
    {   0x00ad, "Connection Capability Control Package" },                    /* H.248.46 */
    {   0x00ae, "Statistic Conditional Reporting Package" },                  /* H.248.47 Amendment 1 */
    {   0x00af, "RTCP HR QoS Statistics Package" },                           /* H.248.48 */
    {   0x00b0, "Received RTCP XR Package" },                                 /* H.248.30 (01/2007) */
    {   0x00b1, "Received RTCP XR Burst Metrics Package" },                   /* H.248.30 (01/2007) */
    {   0x00b2, "ASCI Group call package" },                                  /* 3GPP TS 29.232 v7.4.0 */
    {   0x00b3, "Multimedia Recording Package" },                             /* H.248.9 Amendment 1 */
    {   0x00b4, "H.245 Transport Package" },                                  /* H.248.12 Amendment 2 */
    {   0x00b5, "RTCP Handling package" },                                    /* H.248.57 */
    {   0x00b6, "Gate Management - Outgoing Destination Address/Port Filtering Package" },/* H.248.43 */
    {   0x00b7, "Gate Management - Incoming Protocol Filtering Package" },    /* H.248.43 */
    {   0x00b8, "Gate Management - Outgoing Protocol Filtering Package" },    /* H.248.43 */
    {   0x00b9, "Gate Management - Incoming Filtering Behaviour Package" },   /* H.248.43 */
    {   0x00ba, "Gate Management - Outgoing Filtering Behaviour Package" },   /* H.248.43 */
    {   0x00bb, "Session Description Protocol RFC Package" },                 /* H.248.49 */
    {   0x00bc, "Session Description Protocol Capabilities Package" },        /* H.248.49 */
    {   0x00bd, "NAT Traversal Toolkit - STUN Base Package" },                /* H.248.50 */
    {   0x00be, "NAT Traversal Toolkit - MG STUN Client Package" },           /* H.248.50 */
    {   0x00bf, "NAT Traversal Toolkit - MG TURN Client Package" },           /* H.248.50 */
    {   0x00c0, "NAT Traversal Toolkit - MGC STUN Client Package" },          /* H.248.50 */
    {   0x00c1, "NAT Traversal Toolkit - STUN Information Package" },         /* H.248.50 */
    {   0x00c2, "NAT Traversal Toolkit - MG Act-as STUN Server Package" },    /* H.248.50 */
    {   0x00c3, "NAT Traversal Toolkit - Originate STUN Continuity Check Package" },  /* H.248.50 */
    {   0x00c4, "NAT Traversal Toolkit - MGC Originated STUN Request Package" },      /* H.248.50 */
    {   0x00c5, "NAT Traversal Toolkit - RTP NOOP Request Package" },         /* H.248.50 */
    {   0x00c6, "Termination Connection Model Package" },                     /* H.248.51 */
    {   0x00c7, "QoS Class Package" },                                        /* H.248.52 */
    {   0x00c8, "Traffic Policing Statistics Package" },                      /* H.248.53 */
    {   0x00c9, "Packet Size Package" },                                      /* H.248.53 */
    {   0x00ca, "Pull Mode Package" },                                        /* H.248.55 */
    {   0x00cb, "RTP Application Data Package" },                             /* H.248.58 */
    {   0x00cc, "Event Timestamp Notification Package" },                     /* H.248.59 */
    {   0x00cd, "Resource Management Rules Package" },                        /* H.248.63 */
    {   0x00ce, "Resource Management Configuration Package" },                /* H.248.63 */
    {   0x00cf, "Abstract Resource Management Packages" },                    /* H.248.63 */
    {   0x00d0, "IP layer octets count statistics Package" },                 /* H.248.61 */
    {   0x00d1, "Content of Communication Identity Package" },                /* H.248.60 */
    {   0x00d2, "RSVP extension package" },                                   /* H.248.65 */
    {   0x00d3, "GCP Transport Mode Indication Package" },                    /* H.248.67 */
    {   0x00d4, "IP Router Package" },                                        /* H.248.64 */
    {   0x00d5, "Media Resource Identification Package" },                    /* H.248.66 */
    {   0x00d6, "Range Format Support Package" },                             /* H.248.66 */
    {   0x00d7, "Media Resource Description Expiry Package" },                /* H.248.66 */
    {   0x00d8, "Media Block Size Package" },                                 /* H.248.66 */
    {   0x00d9, "RTSP Media Resource Syntax Package" },                       /* H.248.66 */
    {   0x00da, "RTSP Play Package" },                                        /* H.248.66 */
    {   0x00db, "Signal Pause Package" },                                     /* H.248.66 */
    {   0x00dc, "Data Delivery Speed Adjustme Package" },                     /* H.248.66 */
    {   0x00dd, "Playback Relative Scale Adjustment Package" },               /* H.248.66 */
    {   0x00de, "RTP Information Package" },                                  /* H.248.66 */
    {   0x00df, "RTP Interleaving Package" },                                 /* H.248.66 */
    {   0x00e0, "IP Realm Availability Package" },                            /* H.248.41 Amendment 1 */
    {   0x00e1, "General IP Header QoS Octet Package" },                      /* H.248.52  */
    {   0x00e2, "Re-answer Package" },                                        /* H.248.62  */
    {   0x00e3, "3G Interface Type package" },                                /* 3GPP TS 29.232 v8.4.0 */
    {   0x00e4, "Latch Statistics Package" },                                 /* H.248.37 */
    {   0x00e5, "Floor Control Signalling Package" },                         /* H.248.19 Amendment 2 */
    {   0x00e6, "Include Participant in Mix Package" },                       /* H.248.19 Amendment 2 */
    {   0x00e7, "Speaker Reporting Package" },                                /* H.248.19 Amendment 2 */
    {   0x00e8, "IP Layer Packet Count Statistics Package" },                 /* H.248.61 */
    {   0x00e9, "Removal of Digits and Tones Package" },                      /* H.248.68 */
    {   0x00ea, "MSRP Statistics Package" },                                  /* H.248.69 */
    {   0x00eb, "MSRP Connection Status Package" },                           /* H.248.69 */
    {   0x00ec, "Play Message Package" },                                     /* H.248.69 */
    {   0x00ed, "Delete Stored Message Package" },                            /* H.248.69 */
    {   0x00ee, "Message Session Information Package" },                      /* H.248.69 */
    {   0x00ef, "Message Filtering Package" },                                /* H.248.69 */
    {   0x00f0, "Stored Message Information Package" },                       /* H.248.69 */
    {   0x00f1, "Record Message Package" },                                   /* H.248.69 */
    {   0x00f2, "Digit Dialling Method Information Package" },                /* H.248.70 */
    {   0x00f3, "Digit Dialling Method Information for Extended Digitmap Detection Package" }, /* H.248.70 */
    {   0x00f4, "Digit Dialling Method Information for Enhanced Digitmap Detection Package" }, /* H.248.70 */
    {   0x00f5, "Received RTCP Package " },                                   /* H.248.71 */
    {   0x00f6, "RTP Cumulative Loss Package" },                              /* H.248.71 */
    {   0x00f7, "H.245 Transport Package for SPC use" },                      /* H.248.72 */
    {   0x00f8, "MONA Preference Package" },                                  /* H.248.72 */
    {   0x00f9, "TDM Gain Control Package" },                                 /* H.248.73 */
    {   0x00fa, "Media Start Package" },                                      /* H.248.74 */
    {   0x00fb, "Trim Package" },                                             /* H.248.74 */
    {   0x00fc, "Enhanced Recording Package" },                               /* H.248.74 */
    {   0x00fd, "Enhanced ASR Package" },                                     /* H.248.74      */
    {   0x00fe, "Enhanced TTS Package" },                                     /* H.248.74 */
    {   0x00ff, "Play Offset Control Package" },                              /* H.248.74 */
    {   0x0100, "Enhanced DTMF Detection Package" },                          /* H.248.9 Revised 2009 */
    {   0x0101, "IP Router NAT Package" },                                    /* H.248.64 */
    {   0x0102, "Voice Enrolled Grammar Package" },                           /* H.248.74 */
    {   0x0103, "Filter Group Package" },                                     /* H.248.76 */
    {   0x0104, "RTCP Source Description Package" },                          /* H.248.71 */
    {   0x0105, "Speaker Verification and Identification Package" },          /* H.248.74 */
    {   0x0106, "Package Identifier Publishing and Application Package" },    /* H.248 */
    {   0x0107, "Secure RTP Package " },                                      /* H.248.77 */
    {   0x0108, "MGC Controlled Bearer Level ALG Package" },                  /* H.248.78 */
    {   0x0109, "Enhanced Revised Offer/Answer SDP Support Package" },        /* H.248.80 */
    {   0x010a, "Enhanced SDP Media Capabilities Negotiation Support Package" }, /* H.248.80 */
    {   0x8000, "Ericsson IU" },
    {   0x8001, "Ericsson UMTS and GSM Circuit" },
    {   0x8002, "Ericsson Tone Generator Package" },
    {   0x8003, "Ericsson Line Test Package" },
    {   0x8004, "Nokia Advanced TFO Package" },
    {   0x8005, "Nokia IWF Package" },
    {   0x8006, "Nokia Root Package" },
    {   0x8007, "Nokia Trace Package" },
    {   0x8008, "Ericsson  V5.2 Layer" },
    {   0x8009, "Ericsson Detailed Termination Information Package" },
    {   0x800a, "Nokia Bearer Characteristics Package" },
    {   0x800b, "Nokia Test Call Package" },
    {   0x800c, "Nokia Extended Continuity Package" },
    {   0x800d, "Nokia IPnwR Package" },
    {   0x800e, "Ericsson Tracing Enhancements Package" },
    {   0x800f, "Ericsson Partially Wildcarded TerminationID Package" },
    {   0x8010, "SCTP Stream Handling Package" },
    {0,     NULL}
};

/*
 * This table consist of PackageName + EventName and its corresponding string
 *
 */
static const value_string base_event_name_vals[] = {
    {   0x00000000, "Media stream properties H.248.1 Annex C" },
    {   0x00010000, "g H.248.1 Annex E" },
    {   0x00010001, "g/Cause" },
    {   0x00010002, "g/Signal Completion" },
    {   0x00040000, "tonedet H.248.1 Annex E" },
    {   0x00040001, "tonedet/std(Start tone detected)" },
    {   0x00040002, "tonedet/etd(End tone detected)" },
    {   0x00040003, "tonedet/ltd(Long tone detected)" },
    {   0x00060000, "dd H.248.1 Annex E" },
    {   0x00060001, "dd/std" },
    {   0x00060002, "dd/etd" },
    {   0x00060003, "dd/ltd" },
    {   0x00060004, "dd, DigitMap Completion Event" },
    {   0x00060010, "dd/d0, DTMF character 0" },
    {   0x00060011, "dd/d1, DTMF character 1" },
    {   0x00060012, "dd/d2, DTMF character 2" },
    {   0x00060013, "dd/d3, DTMF character 3" },
    {   0x00060014, "dd/d4, DTMF character 4" },
    {   0x00060015, "dd/d5, DTMF character 5" },
    {   0x00060016, "dd/d6, DTMF character 6" },
    {   0x00060017, "dd/d7, DTMF character 7" },
    {   0x00060018, "dd/d8, DTMF character 8" },
    {   0x00060019, "dd/d9, DTMF character 9" },
    {   0x0006001a, "dd/a, DTMF character A" },
    {   0x0006001b, "dd/b, DTMF character B" },
    {   0x0006001c, "dd/c, DTMF character C" },
    {   0x0006001d, "dd/d, DTMF character D" },
    {   0x00060020, "dd/" "*, DTMF character *" },   /* XXX: hack so checkAPIs & etc won't see a 'start of comment' */
    {   0x00060021, "dd/#, DTMF character #" },
    {   0x00080030, "cd, Dial Tone" },
    {   0x00080031, "cd, Ringing Tone" },
    {   0x00080032, "cd, Busy Tone" },
    {   0x00080033, "cd, Congestion Tone" },
    {   0x00080034, "cd, Special Information Tone" },
    {   0x00080035, "cd, (Recording) Warning Tone" },
    {   0x00080036, "cd, Payphone Recognition Tone" },
    {   0x00080037, "cd, Call Waiting Tone" },
    {   0x00080038, "cd, Caller Waiting Tone" },
    {   0x00090004, "al, onhook" },
    {   0x00090005, "al, offhook" },
    {   0x00090006, "al, flashhook" },
    {   0x0009ffff, "al, *" },
    {   0x000a0005, "ct, Completion of Continuity test" },
    {   0x000b0005, "nt, network failure" },
    {   0x000b0006, "nt, quality alert" },
    {   0x000c0001, "rtp, Payload Transition" },
    {   0x00210000, "Generic Bearer Connection Q.1950 Annex A" },
    {   0x00210001, "GB/BNCChange" },
    {   0x00220001, "BT/TIND (Tunnel Indication)" },
    {   0x002a0001, "H.245/h245msg (Incoming H.245 Message)" },
    {   0x002a0004, "H.245/h245ChC (H.245 Channel Closed)" },
    {   0x00450000, "Inactivity Timer H.248.14" },
    {   0x00450001, "it/ito" },
    {   0x00450002, "it/ito" },
    {   0x00460001, "threegmlc/mod_link_supp (Bearer Modification Support Event)" },
    {   0x00980000, "Hanging Termination Package" },
    {   0x00980001, "Termination Heartbeat" },
    {   0x800a0000, "Nokia Bearer Characteristics Package" },
    {0,     NULL}
};

/*
 * This table consist of PackageName + SignalName and its corresponding string
 */
static const value_string base_signal_name_vals[] = {
    {   0x00000000, "Media stream properties H.248.1 Annex C" },
    {   0x00010000, "g H.248.1 Annex E" },
    {   0x00030001, "tonegen/pt(Play tone)" },
    {   0x00050010, "dg, DTMF character 0" },
    {   0x00050011, "dg, DTMF character 1" },
    {   0x00050012, "dg, DTMF character 2" },
    {   0x00050013, "dg, DTMF character 3" },
    {   0x00050014, "dg, DTMF character 4" },
    {   0x00050015, "dg, DTMF character 5" },
    {   0x00050016, "dg, DTMF character 6" },
    {   0x00050017, "dg, DTMF character 7" },
    {   0x00050018, "dg, DTMF character 8" },
    {   0x00050019, "dg, DTMF character 9" },
    {   0x0005001a, "dg, DTMF character A" },
    {   0x0005001b, "dg, DTMF character B" },
    {   0x0005001c, "dg, DTMF character C" },
    {   0x0005001d, "dg, DTMF character D" },
    {   0x00050020, "dg, DTMF character *" },
    {   0x00050021, "dg, DTMF character #" },
    {   0x00070030, "cg, Dial Tone" },
    {   0x00070031, "cg/rt (Ringing Tone)" },
    {   0x00070032, "cg, Busy Tone" },
    {   0x00070033, "cg, Congestion Tone" },
    {   0x00070034, "cg, Special Information Tone" },
    {   0x00070035, "cg, (Recording) Warning Tone" },
    {   0x00070036, "cg, Payphone Recognition Tone" },
    {   0x00070037, "cg, Call Waiting Tone" },
    {   0x00070038, "cg, Caller Waiting Tone" },
    {   0x00090002, "al, ring" },
    {   0x0009ffff, "al, *" },
    {   0x000a0003, "ct, Continuity test" },
    {   0x000a0004, "ct, Continuity respond" },
    {   0x00210000, "GB Generic Bearer Connection Q.1950 Annex A" },
    {   0x00210001, "GB/EstBNC(Establish BNC)" },
    {   0x00210002, "GB/ModBNC (Modify BNC)" },
    {   0x00210003, "GB/RelBNC(Release BNC)" },
    {   0x002a0001, "H.245/cs (channel state)" },
    {   0x002a0002, "H.245/termtype (Terminal Type)" },
    {   0x002c0001, "H.324/cmod (Communication mode)" },
    {   0x002c0002, "H.324/muxlv (Highest Multiplexing level)" },
    {   0x002c0003, "H.324/demux (Demultiplex)" },
    {   0x002c0004, "H.324/h223capr (Remote H.223 capability)" },
    {   0x002c0005, "H.324/muxtbl_in (Incoming Multiplex Table)" },
    {   0x002c0006, "H.324/muxtbl_out (Outgoing Multiplex Table)" },
    {   0x800a0000, "Nokia Bearer Characteristics Package" },
    {0,     NULL}
};


static const value_string h248_reasons[] = {
    { 400, "Syntax error in message"},
    { 401, "Protocol Error"},
    { 402, "Unauthorized"},
    { 403, "Syntax error in transaction request"},
    { 406, "Version Not Supported"},
    { 410, "Incorrect identifier"},
    { 411, "The transaction refers to an unknown ContextId"},
    { 412, "No ContextIDs available"},
    { 413, "Number of transactions in message exceeds maximum"},    /* [H.248.8 (08/07)] */
    { 421, "Unknown action or illegal combination of actions"},
    { 422, "Syntax Error in Action"},
    { 430, "Unknown TerminationID"},
    { 431, "No TerminationID matched a wildcard"},
    { 432, "Out of TerminationIDs or No TerminationID available"},
    { 433, "TerminationID is already in a Context"},
    { 434, "Max number of Terminations in a Context exceeded"},
    { 435, "Termination ID is not in specified Context"},
    { 440, "Unsupported or unknown Package"},
    { 441, "Missing Remote or Local Descriptor"},
    { 442, "Syntax Error in Command"},
    { 443, "Unsupported or Unknown Command"},
    { 444, "Unsupported or Unknown Descriptor"},
    { 445, "Unsupported or Unknown Property"},
    { 446, "Unsupported or Unknown Parameter"},
    { 447, "Descriptor not legal in this command"},
    { 448, "Descriptor appears twice in a command"},
    { 449, "Unsupported or Unknown Parameter or Property Value"},
    { 450, "No such property in this package"},
    { 451, "No such event in this package"},
    { 452, "No such signal in this package"},
    { 453, "No such statistic in this package"},
    { 454, "No such parameter value in this package"},
    { 455, "Property illegal in this Descriptor"},
    { 456, "Property appears twice in this Descriptor"},
    { 457, "Missing parameter in signal or event"},
    { 458, "Unexpected Event/Request ID"},
    { 459, "Unsupported or Unknown Profile"},
    { 460, "Unable to set statistic on stream"},
    { 461, "Unsupported or Unknown Profile"},                               /*[H.248.18] */

    { 471, "Implied Add for Multiplex failure"},
    { 472, "Required Information Missing"},                                 /*[H.248.8 (08/07)] */
    { 473, "Conflicting Property Values"},                                  /*[H.248.8 (08/07)] */
    { 474, "Invalid SDP Syntax"},                                           /*[H.248.49] */
    { 475, "Unable to pause the playout of the signal"},                    /*[H.248.66] */
    { 476, "Unable to adjust the data delivery speed of the Signal"},       /*[H.248.66] */

    { 477, "Unable to adjust the playback relative scale of the signal"},   /*[H.248.66] */

    { 478, "Behaviour Contradicts Resource Rule"},                          /*[H.248.63] */

    { 500, "Internal software Failure in MG"},
    { 501, "Not Implemented"},
    { 502, "Not ready"},
    { 503, "Service Unavailable"},
    { 504, "Command Received from unauthorized entity"},
    { 505, "Transaction Request Received before a Service Change Reply has been received"},
    { 506, "Number of Transaction Pendings Exceeded"},
    { 510, "Insufficient resources"},
    { 511, "Temporarily Busy"},                                     /* [H.248.8 (08/07)] */
    { 512, "Media Gateway unequipped to detect requested Event"},
    { 513, "Media Gateway unequipped to generate requested Signals"},
    { 514, "Media Gateway cannot send the specified announcement"},
    { 515, "Unsupported Media Type"},
    { 517, "Unsupported or invalid mode"},
    { 518, "Event buffer full"},
    { 519, "Out of space to store digit map"},
    { 520, "Digit Map undefined in the MG"},
    { 521, "Termination is ServiceChanging"},
    { 522, "Functionality Requested in Topology Triple Not Supported"},
    { 526, "Insufficient bandwidth"},
    { 529, "Internal hardware failure in MG"},
    { 530, "Temporary Network failure"},
    { 531, "Permanent Network failure"},
    { 532, "Audited Property, Statistic, Event or Signal does not exist"},
    { 533, "Response exceeds maximum transport PDU size"},
    { 534, "Illegal write or read only property"},
    { 540, "Unexpected initial hook state"},
    { 541, "Unexpected Spare Bit State"},                               /* [H.248.33] */
    { 542, "Command is not allowed on this termination"},
    { 543, "MGC requested event detection timestamp not supported"},    /* [H.248.8 (08/07)] */
    { 581, "Does Not Exist"},
    { 600, "Illegal syntax within an announcement specification"},
    { 601, "Variable type not supported"},
    { 602, "Variable value out of range"},
    { 603, "Category not supported"},
    { 604, "Selector type not supported"},
    { 605, "Selector value not supported"},
    { 606, "Unknown segment ID"},
    { 607, "Mismatch between play specification and provisioned data"},
    { 608, "Provisioning error"},
    { 609, "Invalid offset"},
    { 610, "No free segment IDs"},
    { 611, "Temporary segment not found"},
    { 612, "Segment in use"},
    { 613, "ISP port limit overrun"},
    { 614, "No modems available"},
    { 615, "Calling number unacceptable"},
    { 616, "Called number unacceptable"},
    { 617, "Reserved for H.248.9 return code"},     /* [H.248.9] */
    { 618, "Reserved for H.248.9 return code"},     /* [H.248.9] */
    { 622, "Reserved for H.248.9 return code"},     /* [H.248.9] */
    { 623, "Reserved for H.248.9 return code"},     /* [H.248.9] */
    { 624, "Reserved for H.248.9 return code"},     /* [H.248.9] */
    { 625, "Reserved for H.248.9 return code"},     /* [H.248.9 Amendment 1] */
    { 626, "Reserved for H.248.9 return code"},     /* [H.248.9 Amendment 1] */
    { 627, "Reserved for H.248.9 return code"},     /* [H.248.9 Amendment 1] */
    { 628, "Reserved for H.248.9 return code"},     /* [H.248.9 Amendment 1] */
    { 629, "Reserved for H.248.9 return code"},     /* [H.248.9 Amendment 1] */
    { 700, "Sieve Script Syntax Error"},            /* [H.248.69] */
    { 701, "Unsupported Sieve Require Error"},      /* [H.248.69] */
    { 702, "Sieve Actions Exceeded Error"},         /* [H.248.69] */

    { 900, "Service Restored"},
    { 901, "Cold Boot"},
    { 902, "Warm Boot"},
    { 903, "MGC Directed Change"},
    { 904, "Termination malfunctioning"},
    { 905, "Termination taken out of service"},
    { 906, "Loss of lower layer connectivity (e.g. downstream sync)"},
    { 907, "Transmission Failure"},
    { 908, "MG Impending Failure"},
    { 909, "MGC Impending Failure"},
    { 910, "Media Capability Failure"},
    { 911, "Modem Capability Failure"},
    { 912, "Mux Capability Failure"},
    { 913, "Signal Capability Failure"},
    { 914, "Event Capability Failure"},
    { 915, "State Loss"},
    { 916, "Packages Change"},
    { 917, "Capabilities Change"},
    { 918, "Cancel Graceful"},
    { 919, "Warm Failover"},
    { 920, "Cold Failover"},
    {0,NULL}
};
static value_string_ext h248_reasons_ext = VALUE_STRING_EXT_INIT(h248_reasons);

static const value_string wildcard_modes[] = {
    { 0, "Choose" },
    { 1, "All" },
    { 0, NULL }
};

static const value_string wildcard_levels[] = {
    { 0, "This One Level" },
    { 1, "This Level and those below" },
    { 0, NULL }
};

static h248_curr_info_t curr_info;
static uint32_t error_code;
static uint32_t h248_version; /* h248v1 support */
static gcp_wildcard_t wild_term;
static uint8_t wild_card = 0xFF; /* place to store wildcardField */

                                /* Call the export PDU tap with relevant data */
static void
export_h248_pdu(packet_info *pinfo, tvbuff_t *tvb)
{
    if (have_tap_listener(exported_pdu_tap)) {
        exp_pdu_data_t *exp_pdu_data = export_pdu_create_common_tags(pinfo, "h248", EXP_PDU_TAG_DISSECTOR_NAME);

        exp_pdu_data->tvb_captured_length = tvb_captured_length(tvb);
        exp_pdu_data->tvb_reported_length = tvb_reported_length(tvb);
        exp_pdu_data->pdu_tvb = tvb;

        tap_queue_packet(exported_pdu_tap, pinfo, exp_pdu_data);
    }
}

extern void h248_param_ber_integer(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, int hfid, h248_curr_info_t* u _U_, void* implicit) {
    asn1_ctx_t asn1_ctx;
    asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
    dissect_ber_integer(implicit ? *((bool*)implicit) : false, &asn1_ctx, tree, tvb, 0, hfid, NULL);
}

extern void h248_param_ber_octetstring(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, int hfid, h248_curr_info_t* u _U_, void* implicit) {
    asn1_ctx_t asn1_ctx;
    asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
    dissect_ber_octet_string(implicit ? *((bool*)implicit) : false, &asn1_ctx, tree, tvb, 0, hfid, NULL);
}

extern void h248_param_ber_boolean(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, int hfid, h248_curr_info_t* u _U_, void* implicit) {
    asn1_ctx_t asn1_ctx;
    asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
    dissect_ber_boolean(implicit ? *((bool*)implicit) : false, &asn1_ctx, tree, tvb, 0, hfid, NULL);
}

extern void h248_param_bytes_item(proto_tree* tree,
                             tvbuff_t* tvb,
                             packet_info* pinfo _U_,
                             int hfid,
                             h248_curr_info_t* h248_info _U_,
                             void* lenp ) {
    int len = lenp ? *((int*)lenp) : -1;
    proto_tree_add_item(tree,hfid,tvb,0,len,ENC_NA);
}

extern void h248_param_uint_item(proto_tree* tree,
                                 tvbuff_t* tvb,
                                 packet_info* pinfo _U_,
                                 int hfid,
                                 h248_curr_info_t* h248_info _U_,
                                 void* lenp ) {
    int len = lenp ? *((int*)lenp) : -1;
    proto_tree_add_item(tree,hfid,tvb,0,len,ENC_BIG_ENDIAN);
}

extern void h248_param_external_dissector(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo , int hfid _U_, h248_curr_info_t* u _U_, void* dissector_hdl) {
    call_dissector((dissector_handle_t) dissector_hdl,tvb,pinfo,tree);
}


static const h248_package_t no_package = { 0xffff, &hf_h248_no_pkg, &ett_h248_no_pkg, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL };
static const h248_pkg_sig_t no_signal = { 0, &hf_h248_no_sig, &ett_h248_no_sig, NULL, NULL };
static const h248_pkg_param_t no_param = { 0, &hf_h248_param, h248_param_uint_item,  NULL };
static const h248_pkg_evt_t no_event = { 0, &hf_h248_no_evt, &ett_h248_no_evt, NULL, NULL };

static const h248_package_t *find_package_id(uint16_t pkgid);
static wmem_tree_t* packages;

extern void h248_param_PkgdName(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo , int hfid _U_, h248_curr_info_t* u1 _U_, void* u2 _U_) {
    tvbuff_t *new_tvb = NULL;
    proto_tree *package_tree=NULL;
    uint16_t name_major, name_minor;
    const h248_package_t* pkg = NULL;
    int offset = 0;
    asn1_ctx_t asn1_ctx;
    asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);

    offset = dissect_ber_octet_string(false, &asn1_ctx, tree, tvb, offset, hfid , &new_tvb);

    if (new_tvb) {
        /* this field is always 4 bytes  so just read it into two integers */
        name_major=tvb_get_ntohs(new_tvb, 0);
        name_minor=tvb_get_ntohs(new_tvb, 2);
        pkg = find_package_id(name_major);
        /* do the prettification */
        proto_item_append_text(asn1_ctx.created_item, "  %s (%04x)",
                               val_to_str_const(0, pkg->param_names, "Unknown Package"),
                               name_major);

        if(tree){
            proto_item* pi;
            const char* strval;

            package_tree = proto_item_add_subtree(asn1_ctx.created_item, ett_packagename);
            proto_tree_add_uint_format(package_tree, hf_h248_pkg_name, tvb, offset-4, 2, name_major,
                "%s (0x%04x)", val_to_str_const(0, pkg->param_names, "Unknown Package"), name_major);

            pi = proto_tree_add_uint(package_tree, hf_248_pkg_param, tvb, offset-2, 2, name_minor);

            if (pkg->signal_names && ( strval = try_val_to_str(name_minor, pkg->signal_names) )) {
                strval = wmem_strdup_printf(pinfo->pool, "%s (%d)",strval,name_minor);
            } else {
                strval = wmem_strdup_printf(pinfo->pool, "Unknown (%d)",name_minor);
            }

            proto_item_set_text(pi,"Signal ID: %s", strval);
        }

    }
}


static int dissect_h248_trx_id(bool implicit_tag, packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, uint32_t* trx_id_p) {
    uint64_t trx_id = 0;
    int8_t ber_class;
    bool pc;
    int32_t tag;
    uint32_t len;
    uint32_t i;

    if(!implicit_tag){
        offset=dissect_ber_identifier(pinfo, tree, tvb, offset, &ber_class, &pc, &tag);
        offset=dissect_ber_length(pinfo, tree, tvb, offset, &len, NULL);
    } else {
        len=tvb_reported_length_remaining(tvb, offset);
    }


    if (len > 8 || len < 1) {
        THROW(BoundsError);
    } else {
        for(i=1;i<=len;i++){
            trx_id=(trx_id<<8)|tvb_get_uint8(tvb, offset);
            offset++;
        }
        if (trx_id > 0xffffffff) {
            proto_item* pi = proto_tree_add_uint64(tree, hf_h248_transactionId64, tvb, offset-len, len, trx_id);
            expert_add_info(pinfo, pi, &ei_h248_transactionId64);

            *trx_id_p = 0;

        } else {
            proto_tree_add_uint(tree, hf_h248_transactionId, tvb, offset-len, len, (uint32_t)trx_id);
            *trx_id_p = (uint32_t)trx_id;
        }
    }

    return offset;
}

static int dissect_h248_ctx_id(bool implicit_tag, packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset, uint32_t* ctx_id_p) {
    int8_t ber_class;
    bool pc;
    int32_t tag;
    uint32_t len;
    uint64_t ctx_id = 0;
    uint32_t i;

    if(!implicit_tag){
        offset=dissect_ber_identifier(pinfo, tree, tvb, offset, &ber_class, &pc, &tag);
        offset=dissect_ber_length(pinfo, tree, tvb, offset, &len, NULL);
    } else {
        len=tvb_reported_length_remaining(tvb, offset);
    }


    if (len > 8 || len < 1) {
        THROW(BoundsError);
    } else {
        for(i=1;i<=len;i++){
            ctx_id=(ctx_id<<8)|tvb_get_uint8(tvb, offset);
            offset++;
        }

        if (ctx_id > 0xffffffff) {
            proto_item* pi = proto_tree_add_uint64(tree, hf_h248_context_id64, tvb, offset-len, len, ctx_id);
            expert_add_info(pinfo, pi, &ei_h248_context_id64);

            *ctx_id_p = 0xfffffffd;

        } else {
            proto_item* pi = proto_tree_add_uint(tree, hf_h248_context_id, tvb, offset-len, len, (uint32_t)ctx_id);

            if ( ctx_id ==  NULL_CONTEXT ) {
                proto_item_set_text(pi,"contextId: Null Context(0)");
            } else if ( ctx_id ==  CHOOSE_CONTEXT ) {
                proto_item_set_text(pi,"contextId: $ (Choose Context = 0xfffffffe)");
            } else if ( ctx_id ==  ALL_CONTEXTS ) {
                proto_item_set_text(pi,"contextId: * (All Contexts = 0xffffffff)");
            }

            *ctx_id_p = (uint32_t) ctx_id;
        }
    }

    return offset;
}

static s_h248_package_t *s_find_package_id(uint16_t pkgid) {
    s_h248_package_t *s_pkg = NULL;
    s_pkg = (s_h248_package_t *)wmem_tree_lookup32(packages, (uint32_t)(pkgid));
    return s_pkg;
}

static const h248_package_t *find_package_id(uint16_t pkgid) {
    s_h248_package_t *s_pkg = NULL;
    s_pkg = s_find_package_id(pkgid); /*(packages, GUINT_TO_POINTER((uint32_t)(pkgid))); */
    if (! s_pkg ) return &no_package;
    return s_pkg->pkg;
}

static bool is_pkg_default(uint16_t pkgid) {
    s_h248_package_t *s_pkg = NULL;
    s_pkg = (s_h248_package_t *)wmem_tree_lookup32(packages, (uint32_t)(pkgid));
    if(! s_pkg ) return true;
    return s_pkg->is_default;
}

void h248_register_package(h248_package_t* pkg, pkg_reg_action reg_action) {
    h248_package_t *pkg_found = NULL, *pkg_high = NULL, *pkg_low = NULL;
    s_h248_package_t *s_pkg = NULL;
    value_string *vst;
    bool pkg_default = false;
    int j = 0, idx = 0, i = 0, k = 0;
    if (! packages) {
        /* no packaegs are yet registerd so create tree and add default packages to tree
         */
        packages = wmem_tree_new(wmem_epan_scope()); /* init tree if no entries */
        while (base_package_name_vals[i].strptr != NULL) {
            pkg_found = wmem_new0(wmem_epan_scope(), h248_package_t); /* create a h248 package structure */
            pkg_found->id = base_package_name_vals[i].value;
            vst = (value_string *)wmem_alloc0(wmem_epan_scope(), sizeof(value_string)*2);
            vst[0].strptr = base_package_name_vals[i].strptr;
            pkg_found->param_names = vst;
            pkg_found->hfid = &hf_h248_pkg_name;
            pkg_found->ett = &ett_packagename;
            try_val_to_str_idx((pkg_found->id)<<16,base_event_name_vals, &j);
            /* now look for events and signals that may be defined for package.  If found, create value_strings */
            if (j != -1) {
                j++; idx=j;
                while((base_event_name_vals[j].strptr!=NULL) && (((base_event_name_vals[j].value)>>16) == (pkg_found->id))) {
                    j++;
                };
                if (idx < j) {
                    vst = (value_string *)wmem_alloc0(wmem_epan_scope(), sizeof(value_string)*(j-idx+1));
                    for (k=0;idx<j;k++) {
                        vst[k].strptr = base_event_name_vals[idx].strptr;
                        vst[k].value = (base_event_name_vals[idx].value & 0xffff);
                        idx++;
                    };
                    pkg_found->event_names = vst;
                }
            }
            /* now look at signals */
            if (!try_val_to_str_idx((pkg_found->id)<<16, base_signal_name_vals, &j)) {
                j++; idx=j;
                while((base_signal_name_vals[j].strptr != NULL) && ((base_signal_name_vals[j].value>>16) == (pkg_found->id))) {
                    j++;
                };
                if (idx < j) {
                    vst = (value_string *)wmem_alloc0(wmem_epan_scope(), sizeof(value_string)*(j-idx+1));
                    for (k=0;idx<j;k++) {
                        vst[k].strptr = base_signal_name_vals[idx].strptr;
                        vst[k].value = (base_signal_name_vals[idx].value &0xffff);
                        idx++;
                    };
                    pkg_found->signal_names = vst;
                }
            };
            s_pkg = wmem_new0(wmem_epan_scope(), s_h248_package_t);
            s_pkg->is_default = true;
            s_pkg->pkg = pkg_found;
            wmem_tree_insert32(packages, pkg_found->id, s_pkg);
            i++;
        };
        pkg_found = NULL; /* reset pointer */
    };
    pkg_default = is_pkg_default(pkg->id);
    if (((reg_action==REPLACE_PKG) || (reg_action==ADD_PKG)) && pkg_default) {
        /* add/replace in tree */
        s_pkg = wmem_new0(wmem_epan_scope(), s_h248_package_t);
        s_pkg->is_default = false;
        s_pkg->pkg = (h248_package_t *)pkg;
        wmem_tree_insert32(packages, pkg->id, s_pkg);
        return;
    };
    if(pkg_default) reg_action = MERGE_PKG_HIGH; /* always make new package override default */
    s_pkg = s_find_package_id(pkg->id);
    if (s_pkg == NULL) { /* no need to merge - package not in tree */
        s_pkg = wmem_new0(wmem_epan_scope(), s_h248_package_t);
        s_pkg->is_default = false;
        s_pkg->pkg = (h248_package_t *)pkg;
        wmem_tree_insert32(packages, pkg->id, s_pkg);
        return;
    }
    pkg_found = s_pkg->pkg;
    if (reg_action==MERGE_PKG_HIGH) {
        pkg_high = (h248_package_t *)pkg;
        pkg_low = pkg_found;
    };
    if (reg_action==MERGE_PKG_LOW) {
        pkg_high = pkg_found;
        pkg_low = (h248_package_t *)pkg;
    };
    if(pkg_high) {
        /* if h248_package_t High Priority value !NULL, replace it in the found tree entry else use current entry */
        (pkg_high->hfid ? (pkg_found->hfid=pkg_high->hfid) : (pkg_found->hfid=pkg_low->hfid));
        (pkg_high->ett ? (pkg_found->ett=pkg_high->ett ):( pkg_found->ett=pkg_low->ett));
        (pkg_high->param_names ? (pkg_found->param_names=pkg_high->param_names ):( pkg_found->param_names=pkg_low->param_names));
        (pkg_high->signal_names ? (pkg_found->signal_names=pkg_high->signal_names ):( pkg_found->signal_names=pkg_low->signal_names));
        (pkg_high->event_names ? (pkg_found->event_names=pkg_high->event_names ):( pkg_found->event_names=pkg_low->event_names));
        (pkg_high->stats_names ? (pkg_found->stats_names=pkg_high->stats_names ):( pkg_found->stats_names=pkg_low->stats_names));
        (pkg_high->properties ? (pkg_found->properties=pkg_high->properties ):( pkg_found->properties=pkg_low->properties));
        (pkg_high->signals ? (pkg_found->signals=pkg_high->signals ):( pkg_found->signals=pkg_low->signals));
        (pkg_high->events ? (pkg_found->events=pkg_high->events ):( pkg_found->events=pkg_low->events));
        (pkg_high->statistics ? (pkg_found->statistics=pkg_high->statistics ):( pkg_found->statistics=pkg_low->statistics));
        s_pkg->pkg = pkg_found;
        s_pkg->is_default = false;
    }
}


static uint32_t packageandid;

static int dissect_h248_PkgdName(bool implicit_tag, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
    tvbuff_t *new_tvb = NULL;
    proto_tree *package_tree=NULL;
    uint16_t name_major, name_minor;
    const h248_package_t* pkg = NULL;

    offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index, &new_tvb);

    if (new_tvb) {
        /* this field is always 4 bytes  so just read it into two integers */
        name_major=tvb_get_ntohs(new_tvb, 0);
        name_minor=tvb_get_ntohs(new_tvb, 2);
        packageandid=(name_major<<16)|name_minor;

        pkg = find_package_id(name_major);
        /* do the prettification */
        proto_item_append_text(actx->created_item, "  %s (%04x)",
                               val_to_str_const(0, pkg->param_names, "Unknown Package"),
                               name_major);

        if(tree){
            package_tree = proto_item_add_subtree(actx->created_item, ett_packagename);
            proto_tree_add_uint_format(package_tree, hf_h248_pkg_name, tvb, offset-4, 2, name_major,
                "PkgName: %s (0x%04x)", val_to_str_const(0, pkg->param_names, "Unknown Package"), name_major);
        }

        {
            proto_item* pi = proto_tree_add_uint(package_tree, hf_248_pkg_param, tvb, offset-2, 2, name_minor);
            const char* strval;

            if (pkg->param_names && ( strval = try_val_to_str(name_minor, pkg->param_names) )) {
                strval = wmem_strdup_printf(actx->pinfo->pool, "%s (%d)",strval,name_minor);
            } else {
                strval = wmem_strdup_printf(actx->pinfo->pool, "Unknown (%d)",name_minor);
            }

            proto_item_set_text(pi,"Parameter: %s", strval);
        }
    } else {
        pkg = &no_package;
    }

    curr_info.pkg = pkg;

    return offset;
}

static int dissect_h248_EventName(bool implicit_tag, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
    tvbuff_t *new_tvb;
    proto_tree *package_tree=NULL;
    uint16_t name_major, name_minor;
    const h248_package_t* pkg = NULL;
    const h248_pkg_evt_t* evt = NULL;

    offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index, &new_tvb);

    if (new_tvb) {
        /* this field is always 4 bytes  so just read it into two integers */
        name_major=tvb_get_ntohs(new_tvb, 0);
        name_minor=tvb_get_ntohs(new_tvb, 2);
        packageandid=(name_major<<16)|name_minor;

        pkg = find_package_id(name_major);
        /* do the prettification */
        proto_item_append_text(actx->created_item, "  %s (%04x)",
                               val_to_str_const(0, pkg->param_names, "Unknown Package"),
                               name_major);
        if(tree){
            package_tree = proto_item_add_subtree(actx->created_item, ett_packagename);
        }
        proto_tree_add_uint_format(package_tree, hf_h248_pkg_name, tvb, offset-4, 2, name_major,
            "%s (0x%04x)", val_to_str_const(0, pkg->param_names, "Unknown Package"), name_major);

        curr_info.pkg = pkg;

        if (pkg->events) {
            for (evt = pkg->events; evt->hfid; evt++) {
                if (name_minor == evt->id) {
                    break;
                }
            }

            if (! evt->hfid) evt = &no_event;
        } else {
            evt = &no_event;
        }

        curr_info.evt = evt;

        {
            proto_item* pi = proto_tree_add_uint(package_tree, hf_h248_event_code, tvb, offset-2, 2, name_minor);
            const char* strval;

            if (pkg->event_names && ( strval = try_val_to_str(name_minor, pkg->event_names) )) {
                strval = wmem_strdup_printf(actx->pinfo->pool, "%s (%d)",strval,name_minor);
            } else {
                strval = wmem_strdup_printf(actx->pinfo->pool, "Unknown (%d)",name_minor);
            }

            proto_item_set_text(pi,"Event ID: %s", strval);
        }

    } else {
        curr_info.pkg = &no_package;
        curr_info.evt = &no_event;
    }

    return offset;
}



static int dissect_h248_SignalName(bool implicit_tag , tvbuff_t *tvb, int offset,  asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
    tvbuff_t *new_tvb;
    proto_tree *package_tree=NULL;
    uint16_t name_major, name_minor;
    const h248_package_t* pkg = NULL;
    const h248_pkg_sig_t* sig;

    offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index, &new_tvb);

    if (new_tvb) {
        /* this field is always 4 bytes so just read it into two integers */
        name_major=tvb_get_ntohs(new_tvb, 0);
        name_minor=tvb_get_ntohs(new_tvb, 2);
        packageandid=(name_major<<16)|name_minor;

        pkg = find_package_id(name_major);
        /* do the prettification */
        proto_item_append_text(actx->created_item, "  %s (%04x)",
                               val_to_str_const(0, pkg->param_names, "Unknown Package"),
                               name_major);
        if(tree){
            package_tree = proto_item_add_subtree(actx->created_item, ett_packagename);
        }
        proto_tree_add_uint_format(package_tree, hf_h248_pkg_name, tvb, offset-4, 2, name_major,
            "%s (0x%04x)", val_to_str_const(0, pkg->param_names, "Unknown Package"), name_major);

        if (pkg->signals) {
            for (sig = pkg->signals; sig->hfid; sig++) {
                if (name_minor == sig->id) {
                    break;
                }
            }

            if (! sig->hfid) sig = &no_signal;

            curr_info.pkg = pkg;
            curr_info.sig = sig;
        } else {
            curr_info.pkg = &no_package;
            curr_info.sig = &no_signal;
        }

        {
            proto_item* pi = proto_tree_add_uint(package_tree, hf_h248_signal_code, tvb, offset-2, 2, name_minor);
            const char* strval;

            if (pkg->signal_names && ( strval = try_val_to_str(name_minor, pkg->signal_names) )) {
                strval = wmem_strdup_printf(actx->pinfo->pool, "%s (%d)",strval,name_minor);
            } else {
                strval = wmem_strdup_printf(actx->pinfo->pool, "Unknown (%d)",name_minor);
            }

            proto_item_set_text(pi,"Signal ID: %s", strval);
        }

    } else {
        curr_info.pkg = &no_package;
        curr_info.sig = &no_signal;
    }

    return offset;
}

static int dissect_h248_PropertyID(bool implicit_tag _U_, tvbuff_t *tvb, int offset,  asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index _U_) {

    int8_t ber_class;
    bool pc, ind;
    int32_t tag;
    uint32_t len;
    uint16_t name_minor;
    int end_offset;
    const h248_package_t* pkg;
    const h248_pkg_param_t* prop;
    tvbuff_t *next_tvb = NULL;

    offset=dissect_ber_identifier(actx->pinfo, tree, tvb, offset, &ber_class, &pc, &tag);
    offset=dissect_ber_length(actx->pinfo, tree, tvb, offset, &len, &ind);
    end_offset=offset+len;

    if( (ber_class!=BER_CLASS_UNI)
      ||(tag!=BER_UNI_TAG_OCTETSTRING) ){
        proto_tree_add_expert_format(tree, actx->pinfo, &ei_h248_octet_string_expected, tvb, offset-2, 2,
            "H.248 BER Error: OctetString expected but Class:%d PC:%d Tag:%d was unexpected", ber_class, pc, tag);
        return end_offset;
    }

    next_tvb = tvb_new_subset_length(tvb,offset,len);

    name_minor = packageandid & 0xffff;

    pkg = (curr_info.pkg) ? curr_info.pkg : &no_package;

    if (pkg->properties) {
        for (prop = pkg->properties; prop && prop->hfid; prop++) {
            if (name_minor == prop->id) {
                break;
            }
        }
    } else {
        prop = &no_param;
    }
    if (prop && prop->hfid && prop->dissector) {
       prop->dissector(tree, next_tvb, actx->pinfo, *(prop->hfid), &curr_info, prop->data);
    }

    return end_offset;
}



static int dissect_h248_SigParameterName(bool implicit_tag _U_, tvbuff_t *tvb, int offset,  asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index _U_) {
    tvbuff_t *next_tvb;
    uint32_t param_id = 0xffffffff;
    const h248_pkg_param_t* sigpar;
    const char* strval;
    proto_item* pi;

    offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset,  hf_index, &next_tvb);
    pi = actx->created_item;

    switch(tvb_reported_length(next_tvb)) {
        case 4: param_id = tvb_get_ntohl(next_tvb,0); break;
        case 3: param_id = tvb_get_ntoh24(next_tvb,0); break;
        case 2: param_id = tvb_get_ntohs(next_tvb,0); break;
        case 1: param_id = tvb_get_uint8(next_tvb,0); break;
        default: break;
    }

    curr_info.par = &no_param;

    if (curr_info.sig && curr_info.sig->parameters) {
        for(sigpar = curr_info.sig->parameters; sigpar->hfid; sigpar++) {
            if (sigpar->id == param_id) {
                curr_info.par = sigpar;
                break;
            }
        }
    }

    if (curr_info.sig && curr_info.sig->param_names && ( strval = try_val_to_str(param_id, curr_info.sig->param_names) )) {
        strval = wmem_strdup_printf(actx->pinfo->pool, "%s (%d)",strval,param_id);
    } else {
        strval = wmem_strdup_printf(actx->pinfo->pool, "Unknown (%d)",param_id);
    }

    proto_item_set_text(pi,"Parameter: %s", strval);

    return offset;
}

static int dissect_h248_SigParamValue(bool implicit_tag _U_, tvbuff_t *tvb, int offset,  asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index _U_) {
    int end_offset;
    int8_t ber_class;
    bool pc, ind;
    int32_t tag;
    uint32_t len;
    tvbuff_t *next_tvb = NULL;

    offset=dissect_ber_identifier(actx->pinfo, tree, tvb, offset, &ber_class, &pc, &tag);
    offset=dissect_ber_length(actx->pinfo, tree, tvb, offset, &len, &ind);
    end_offset=offset+len;

    if( (ber_class!=BER_CLASS_UNI)
        ||(tag!=BER_UNI_TAG_OCTETSTRING) ){
        proto_tree_add_expert_format(tree, actx->pinfo, &ei_h248_octet_string_expected, tvb, offset-2, 2,
            "H.248 BER Error: OctetString expected but Class:%d PC:%d Tag:%d was unexpected", ber_class, pc, tag);
        return end_offset;
    }

    next_tvb = tvb_new_subset_length(tvb,offset,len);

    if ( curr_info.par && curr_info.par->dissector) {
        curr_info.par->dissector(tree, next_tvb, actx->pinfo, *(curr_info.par->hfid), &curr_info, curr_info.par->data);
    }

    return end_offset;
}

static int dissect_h248_SigParamValueV1(bool implicit_tag _U_, tvbuff_t *tvb, int offset _U_,  asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index _U_) {
    return dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);
}


static int dissect_h248_EventParameterName(bool implicit_tag _U_, tvbuff_t *tvb, int offset,  asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index _U_) {
    tvbuff_t *next_tvb;
    uint32_t param_id = 0xffffffff;
    const h248_pkg_param_t* evtpar;
    const char* strval;
    proto_item* pi;

    offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index, &next_tvb);
    pi = actx->created_item;

    if (next_tvb) {
        switch(tvb_reported_length(next_tvb)) {
            case 4: param_id = tvb_get_ntohl(next_tvb,0); break;
            case 3: param_id = tvb_get_ntoh24(next_tvb,0); break;
            case 2: param_id = tvb_get_ntohs(next_tvb,0); break;
            case 1: param_id = tvb_get_uint8(next_tvb,0); break;
            default: break;
        }
    }


    curr_info.par = &no_param;

    if (curr_info.evt && curr_info.evt->parameters) {
        for(evtpar = curr_info.evt->parameters; evtpar->hfid; evtpar++) {
            if (evtpar->id == param_id) {
                curr_info.par = evtpar;
                break;
            }
        }
    } else {
        curr_info.par = &no_param;
    }

    if (curr_info.evt && curr_info.evt->param_names && ( strval = try_val_to_str(param_id, curr_info.evt->param_names) )) {
        strval = wmem_strdup_printf(actx->pinfo->pool, "%s (%d)",strval,param_id);
    } else {
        strval = wmem_strdup_printf(actx->pinfo->pool, "Unknown (%d)",param_id);
    }

    proto_item_set_text(pi,"Parameter: %s", strval);


    return offset;
}

static int dissect_h248_EventParamValue(bool implicit_tag _U_, tvbuff_t *tvb, int offset,  asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index _U_) {
    tvbuff_t *next_tvb;
    int end_offset;
    int8_t ber_class;
    bool pc, ind;
    int32_t tag;
    uint32_t len;

    offset=dissect_ber_identifier(actx->pinfo, tree, tvb, offset, &ber_class, &pc, &tag);
    offset=dissect_ber_length(actx->pinfo, tree, tvb, offset, &len, &ind);
    end_offset=offset+len;

    if( (ber_class!=BER_CLASS_UNI)
        ||(tag!=BER_UNI_TAG_OCTETSTRING) ){
        proto_tree_add_expert_format(tree, actx->pinfo, &ei_h248_octet_string_expected, tvb, offset-2, 2,
            "H.248 BER Error: OctetString expected but Class:%d PC:%d Tag:%d was unexpected", ber_class, pc, tag);
        return end_offset;
    }

    next_tvb = tvb_new_subset_length(tvb,offset,len);

    if ( curr_info.par && curr_info.par->dissector) {
        curr_info.par->dissector(tree, next_tvb, actx->pinfo, *(curr_info.par->hfid), &curr_info, curr_info.par->data);
    }

    return end_offset;
}

static int dissect_h248_EventParamValueV1(bool implicit_tag _U_, tvbuff_t *tvb, int offset _U_,  asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index _U_) {
    return dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index, &tvb);
}


static int dissect_h248_MtpAddress(bool implicit_tag, tvbuff_t *tvb, int offset,  asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
    tvbuff_t *new_tvb;
    proto_tree *mtp_tree=NULL;
    uint32_t val;
    int i, len, old_offset;

    old_offset=offset;
    offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index, &new_tvb);

    if (new_tvb) {
        /* this field is either 2 or 4 bytes  so just read it into an integer */
        val=0;
        len=tvb_reported_length(new_tvb);
        for(i=0;i<len;i++){
            val= (val<<8)|tvb_get_uint8(new_tvb, i);
        }

        /* do the prettification */
        proto_item_append_text(actx->created_item, "  NI = %d, PC = %d ( %d-%d )", val&0x03,val>>2,val&0x03,val>>2);
        if(tree){
            mtp_tree = proto_item_add_subtree(actx->created_item, ett_mtpaddress);
        }
        proto_tree_add_uint(mtp_tree, hf_h248_mtpaddress_ni, tvb, old_offset, offset-old_offset, val&0x03);
        proto_tree_add_uint(mtp_tree, hf_h248_mtpaddress_pc, tvb, old_offset, offset-old_offset, val>>2);
    }

    return offset;
}

#define H248_TAP() do { if (keep_persistent_data && curr_info.cmd) tap_queue_packet(h248_tap, actx->pinfo, curr_info.cmd); } while(0)

/*--- Cyclic dependencies ---*/

/* SecondEventsDescriptor -> SecondEventsDescriptor/eventList -> SecondRequestedEvent -> SecondRequestedActions -> NotifyBehaviour -> RegulatedEmbeddedDescriptor -> SecondEventsDescriptor */
static int dissect_h248_SecondEventsDescriptor(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);




static int
dissect_h248_SecurityParmIndex(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_h248_SequenceNum(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_h248_AuthData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t AuthenticationHeader_sequence[] = {
  { &hf_h248_secParmIndex   , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_SecurityParmIndex },
  { &hf_h248_seqNum         , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_h248_SequenceNum },
  { &hf_h248_ad             , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_h248_AuthData },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_AuthenticationHeader(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AuthenticationHeader_sequence, hf_index, ett_h248_AuthenticationHeader);

  return offset;
}



static int
dissect_h248_T_version(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
	  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &h248_version);


  return offset;
}



static int
dissect_h248_OCTET_STRING_SIZE_4(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_h248_INTEGER_0_65535(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t IP4Address_sequence[] = {
  { &hf_h248_iP4Address     , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_OCTET_STRING_SIZE_4 },
  { &hf_h248_portNumber     , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_INTEGER_0_65535 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_IP4Address(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   IP4Address_sequence, hf_index, ett_h248_IP4Address);

  return offset;
}



static int
dissect_h248_OCTET_STRING_SIZE_16(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t IP6Address_sequence[] = {
  { &hf_h248_iP6Address     , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_OCTET_STRING_SIZE_16 },
  { &hf_h248_portNumber     , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_INTEGER_0_65535 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_IP6Address(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   IP6Address_sequence, hf_index, ett_h248_IP6Address);

  return offset;
}



static int
dissect_h248_IA5String(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t DomainName_sequence[] = {
  { &hf_h248_domName        , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_IA5String },
  { &hf_h248_portNumber     , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_INTEGER_0_65535 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_DomainName(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DomainName_sequence, hf_index, ett_h248_DomainName);

  return offset;
}



static int
dissect_h248_PathName(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static const value_string h248_MId_vals[] = {
  {   0, "ip4Address" },
  {   1, "ip6Address" },
  {   2, "domainName" },
  {   3, "deviceName" },
  {   4, "mtpAddress" },
  { 0, NULL }
};

static const ber_choice_t MId_choice[] = {
  {   0, &hf_h248_ip4Address     , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_IP4Address },
  {   1, &hf_h248_ip6Address     , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_h248_IP6Address },
  {   2, &hf_h248_domainName     , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_h248_DomainName },
  {   3, &hf_h248_deviceName     , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_h248_PathName },
  {   4, &hf_h248_mtpAddress     , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_h248_MtpAddress },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_MId(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 MId_choice, hf_index, ett_h248_MId,
                                 NULL);

  return offset;
}




static int
dissect_h248_T_errorCode(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index, &error_code);
    expert_add_info(actx->pinfo, actx->created_item, &ei_h248_errored_command);

    if (curr_info.cmd) {
        gcp_cmd_set_error(curr_info.cmd,error_code);
    } else if (curr_info.trx) {
        gcp_trx_set_error(curr_info.trx,error_code);
    }

  return offset;
}



static int
dissect_h248_ErrorText(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t ErrorDescriptor_sequence[] = {
  { &hf_h248_errorCode      , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_T_errorCode },
  { &hf_h248_errorText      , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_ErrorText },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_ErrorDescriptor(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ErrorDescriptor_sequence, hf_index, ett_h248_ErrorDescriptor);

  return offset;
}



static int
dissect_h248_TransactionId(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_h248_T_transactionId(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    uint32_t trx_id = 0;
	offset = dissect_h248_trx_id(implicit_tag, actx->pinfo, tree, tvb, offset, &trx_id);
    curr_info.trx = gcp_trx(curr_info.msg, trx_id, GCP_TRX_REQUEST, actx->pinfo, keep_persistent_data);
    error_code = 0;

  return offset;
}




static int
dissect_h248_ContextId(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    uint32_t ctx_id = 0;
	offset = dissect_h248_ctx_id(implicit_tag, actx->pinfo, tree, tvb, offset, &ctx_id);
    curr_info.ctx = gcp_ctx(curr_info.msg,curr_info.trx,ctx_id,actx->pinfo,keep_persistent_data);
    curr_info.cmd = NULL;
    curr_info.term = NULL;

  return offset;
}



static int
dissect_h248_INTEGER_0_15(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_h248_BOOLEAN(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_h248_WildcardField(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    tvbuff_t* new_tvb;
    offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index, &new_tvb);
    tree = proto_item_add_subtree(actx->created_item,ett_wildcard);
    proto_tree_add_item(tree,hf_h248_term_wild_type,new_tvb,0,1,ENC_BIG_ENDIAN);
    proto_tree_add_item(tree,hf_h248_term_wild_level,new_tvb,0,1,ENC_BIG_ENDIAN);
    proto_tree_add_item(tree,hf_h248_term_wild_position,new_tvb,0,1,ENC_BIG_ENDIAN);

    wild_term = tvb_get_uint8(new_tvb,0) & 0x80 ? GCP_WILDCARD_CHOOSE : GCP_WILDCARD_ALL;
    /* limitation: assume only one wildcard is used */
    wild_card = tvb_get_uint8(new_tvb,0);


  return offset;
}


static const ber_sequence_t SEQUENCE_OF_WildcardField_sequence_of[1] = {
  { &hf_h248_wildcard_item  , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_h248_WildcardField },
};

static int
dissect_h248_SEQUENCE_OF_WildcardField(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_WildcardField_sequence_of, hf_index, ett_h248_SEQUENCE_OF_WildcardField);

  return offset;
}



static int
dissect_h248_T_terminationId(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
	tvbuff_t* new_tvb;
	h248_term_info_t term_info;

	term_info.wild_card = wild_card;
	term_info.str = NULL;

	offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index, &new_tvb);

	if (new_tvb) {
		curr_info.term->len = tvb_reported_length(new_tvb);
		curr_info.term->type = 0; /* unknown */

		if (h248_term_handle) {
			call_dissector_with_data(h248_term_handle, new_tvb, actx->pinfo, tree, &term_info);
			wild_card = 0xFF;
		}

		if (curr_info.term->len) {
			curr_info.term->buffer = (uint8_t *)tvb_memdup(actx->pinfo->pool,new_tvb,0,curr_info.term->len);
			if(term_info.str){
				curr_info.term->str = wmem_strdup_printf(actx->pinfo->pool, "%s %s",
											bytes_to_str_punct(actx->pinfo->pool,curr_info.term->buffer,curr_info.term->len, 0),
											term_info.str);
			}else{
				curr_info.term->str = bytes_to_str_punct(actx->pinfo->pool,curr_info.term->buffer,curr_info.term->len, 0);
			}
		}


		curr_info.term = gcp_cmd_add_term(curr_info.msg, curr_info.trx, curr_info.cmd, curr_info.term, wild_term, actx->pinfo, keep_persistent_data);

	} else {
		curr_info.term->len = 0;
		curr_info.term->buffer = (uint8_t*)wmem_strdup(actx->pinfo->pool, "");
		curr_info.term->str = wmem_strdup(actx->pinfo->pool, "?");
	}

  return offset;
}


static const ber_sequence_t TerminationID_sequence[] = {
  { &hf_h248_wildcard       , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_SEQUENCE_OF_WildcardField },
  { &hf_h248_terminationId  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_h248_T_terminationId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_TerminationID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    curr_info.term = wmem_new0(actx->pinfo->pool, gcp_term_t);
    wild_term = GCP_WILDCARD_NONE;
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TerminationID_sequence, hf_index, ett_h248_TerminationID);

  return offset;
}


static const value_string h248_T_topologyDirection_vals[] = {
  {   0, "bothway" },
  {   1, "isolate" },
  {   2, "oneway" },
  { 0, NULL }
};


static int
dissect_h248_T_topologyDirection(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_h248_StreamID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string h248_T_topologyDirectionExtension_vals[] = {
  {   0, "onewayexternal" },
  {   1, "onewayboth" },
  { 0, NULL }
};


static int
dissect_h248_T_topologyDirectionExtension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t TopologyRequest_sequence[] = {
  { &hf_h248_terminationFrom, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_TerminationID },
  { &hf_h248_terminationTo  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_h248_TerminationID },
  { &hf_h248_topologyDirection, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_h248_T_topologyDirection },
  { &hf_h248_streamID       , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_StreamID },
  { &hf_h248_topologyDirectionExtension, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_T_topologyDirectionExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_TopologyRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TopologyRequest_sequence, hf_index, ett_h248_TopologyRequest);

  return offset;
}


static const ber_sequence_t T_topologyReq_sequence_of[1] = {
  { &hf_h248_topologyReq_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_h248_TopologyRequest },
};

static int
dissect_h248_T_topologyReq(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
      curr_info.cmd = gcp_cmd(curr_info.msg,curr_info.trx,curr_info.ctx,GCP_CMD_TOPOLOGY_REQ,offset,actx->pinfo,keep_persistent_data);
      H248_TAP();
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_topologyReq_sequence_of, hf_index, ett_h248_T_topologyReq);

      curr_info.cmd = NULL;
  return offset;
}



static int
dissect_h248_Iepscallind_BOOL(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}




static int
dissect_h248_PropertyName(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_h248_PkgdName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static const ber_sequence_t SEQUENCE_OF_PropertyID_sequence_of[1] = {
  { &hf_h248_propertyParamValue_item, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_h248_PropertyID },
};

static int
dissect_h248_SEQUENCE_OF_PropertyID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_PropertyID_sequence_of, hf_index, ett_h248_SEQUENCE_OF_PropertyID);

  return offset;
}


static const value_string h248_Relation_vals[] = {
  {   0, "greaterThan" },
  {   1, "smallerThan" },
  {   2, "unequalTo" },
  { 0, NULL }
};


static int
dissect_h248_Relation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string h248_PropParm_extraInfo_vals[] = {
  {   0, "relation" },
  {   1, "range" },
  {   2, "sublist" },
  { 0, NULL }
};

static const ber_choice_t PropParm_extraInfo_choice[] = {
  {   0, &hf_h248_relation       , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_Relation },
  {   1, &hf_h248_range          , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_h248_BOOLEAN },
  {   2, &hf_h248_sublist        , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_h248_BOOLEAN },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_PropParm_extraInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 PropParm_extraInfo_choice, hf_index, ett_h248_PropParm_extraInfo,
                                 NULL);

  return offset;
}


static const ber_sequence_t PropertyParm_sequence[] = {
  { &hf_h248_propertyName   , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_PropertyName },
  { &hf_h248_propertyParamValue, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_h248_SEQUENCE_OF_PropertyID },
  { &hf_h248_propParm_extraInfo, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_PropParm_extraInfo },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_PropertyParm(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PropertyParm_sequence, hf_index, ett_h248_PropertyParm);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_PropertyParm_sequence_of[1] = {
  { &hf_h248_contextProp_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_h248_PropertyParm },
};

static int
dissect_h248_SEQUENCE_OF_PropertyParm(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_PropertyParm_sequence_of, hf_index, ett_h248_SEQUENCE_OF_PropertyParm);

  return offset;
}



static int
dissect_h248_ContextIDinList(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_ContextIDinList_sequence_of[1] = {
  { &hf_h248_contextList_item, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_h248_ContextIDinList },
};

static int
dissect_h248_SEQUENCE_OF_ContextIDinList(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_ContextIDinList_sequence_of, hf_index, ett_h248_SEQUENCE_OF_ContextIDinList);

  return offset;
}


static const ber_sequence_t ContextRequest_sequence[] = {
  { &hf_h248_priority       , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_INTEGER_0_15 },
  { &hf_h248_emergency      , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_BOOLEAN },
  { &hf_h248_topologyReq    , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_T_topologyReq },
  { &hf_h248_iepscallind_BOOL, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_Iepscallind_BOOL },
  { &hf_h248_contextProp    , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_SEQUENCE_OF_PropertyParm },
  { &hf_h248_contextList    , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_SEQUENCE_OF_ContextIDinList },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_ContextRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ContextRequest_sequence, hf_index, ett_h248_ContextRequest);

  return offset;
}



static int
dissect_h248_NULL(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t IndAudPropertyParm_sequence[] = {
  { &hf_h248_name           , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_PkgdName },
  { &hf_h248_propertyParms  , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_PropertyParm },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_IndAudPropertyParm(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   IndAudPropertyParm_sequence, hf_index, ett_h248_IndAudPropertyParm);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_IndAudPropertyParm_sequence_of[1] = {
  { &hf_h248_contextPropAud_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_h248_IndAudPropertyParm },
};

static int
dissect_h248_SEQUENCE_OF_IndAudPropertyParm(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_IndAudPropertyParm_sequence_of, hf_index, ett_h248_SEQUENCE_OF_IndAudPropertyParm);

  return offset;
}


static const value_string h248_SelectLogic_vals[] = {
  {   0, "andAUDITSelect" },
  {   1, "orAUDITSelect" },
  { 0, NULL }
};

static const ber_choice_t SelectLogic_choice[] = {
  {   0, &hf_h248_andAUDITSelect , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_NULL },
  {   1, &hf_h248_orAUDITSelect  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_h248_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_SelectLogic(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 SelectLogic_choice, hf_index, ett_h248_SelectLogic,
                                 NULL);

  return offset;
}


static const ber_sequence_t ContextAttrAuditRequest_sequence[] = {
  { &hf_h248_topology       , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_NULL },
  { &hf_h248_cAAREmergency  , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_NULL },
  { &hf_h248_cAARPriority   , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_NULL },
  { &hf_h248_iepscallind    , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_NULL },
  { &hf_h248_contextPropAud , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_SEQUENCE_OF_IndAudPropertyParm },
  { &hf_h248_selectpriority , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_INTEGER_0_15 },
  { &hf_h248_selectemergency, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_BOOLEAN },
  { &hf_h248_selectiepscallind, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_BOOLEAN },
  { &hf_h248_selectLogic    , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_h248_SelectLogic },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_ContextAttrAuditRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ContextAttrAuditRequest_sequence, hf_index, ett_h248_ContextAttrAuditRequest);

  return offset;
}



static int
dissect_h248_T_contextAttrAuditReq(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
      curr_info.cmd = gcp_cmd(curr_info.msg,curr_info.trx,curr_info.ctx,GCP_CMD_CTX_ATTR_AUDIT_REQ,offset,actx->pinfo,keep_persistent_data);
      H248_TAP();
  offset = dissect_h248_ContextAttrAuditRequest(implicit_tag, tvb, offset, actx, tree, hf_index);

      curr_info.cmd = NULL;
  return offset;
}


static const ber_sequence_t TerminationIDList_sequence_of[1] = {
  { &hf_h248_TerminationIDList_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_h248_TerminationID },
};

static int
dissect_h248_TerminationIDList(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      TerminationIDList_sequence_of, hf_index, ett_h248_TerminationIDList);

  return offset;
}


static const value_string h248_EventBufferControl_vals[] = {
  {   0, "off" },
  {   1, "lockStep" },
  { 0, NULL }
};


static int
dissect_h248_EventBufferControl(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string h248_ServiceState_vals[] = {
  {   0, "test" },
  {   1, "outOfSvc" },
  {   2, "inSvc" },
  { 0, NULL }
};


static int
dissect_h248_ServiceState(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t TerminationStateDescriptor_sequence[] = {
  { &hf_h248_tSDpropertyParms, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_SEQUENCE_OF_PropertyParm },
  { &hf_h248_tSEventBufferControl, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_EventBufferControl },
  { &hf_h248_serviceState   , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_ServiceState },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_TerminationStateDescriptor(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TerminationStateDescriptor_sequence, hf_index, ett_h248_TerminationStateDescriptor);

  return offset;
}


static const value_string h248_StreamMode_vals[] = {
  {   0, "sendOnly" },
  {   1, "recvOnly" },
  {   2, "sendRecv" },
  {   3, "inactive" },
  {   4, "loopBack" },
  { 0, NULL }
};


static int
dissect_h248_StreamMode(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t LocalControlDescriptor_sequence[] = {
  { &hf_h248_streamMode     , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_StreamMode },
  { &hf_h248_reserveValue   , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_BOOLEAN },
  { &hf_h248_reserveGroup   , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_BOOLEAN },
  { &hf_h248_lCDpropertyParms, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_h248_SEQUENCE_OF_PropertyParm },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_LocalControlDescriptor(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   LocalControlDescriptor_sequence, hf_index, ett_h248_LocalControlDescriptor);

  return offset;
}


static const ber_sequence_t PropertyGroup_sequence_of[1] = {
  { &hf_h248_PropertyGroup_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_h248_PropertyParm },
};

static int
dissect_h248_PropertyGroup(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      PropertyGroup_sequence_of, hf_index, ett_h248_PropertyGroup);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_PropertyGroup_sequence_of[1] = {
  { &hf_h248_propGrps_item  , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_h248_PropertyGroup },
};

static int
dissect_h248_SEQUENCE_OF_PropertyGroup(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_PropertyGroup_sequence_of, hf_index, ett_h248_SEQUENCE_OF_PropertyGroup);

  return offset;
}


static const ber_sequence_t LocalRemoteDescriptor_sequence[] = {
  { &hf_h248_propGrps       , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_SEQUENCE_OF_PropertyGroup },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_LocalRemoteDescriptor(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   LocalRemoteDescriptor_sequence, hf_index, ett_h248_LocalRemoteDescriptor);

  return offset;
}



static int
dissect_h248_StatName(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_h248_PkgdName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_h248_OCTET_STRING(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t Value_sequence_of[1] = {
  { &hf_h248_Value_item     , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_h248_OCTET_STRING },
};

static int
dissect_h248_Value(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      Value_sequence_of, hf_index, ett_h248_Value);

  return offset;
}



static int
dissect_h248_StatValue(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_h248_Value(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t StatisticsParameter_sequence[] = {
  { &hf_h248_statName       , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_StatName },
  { &hf_h248_statValue      , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_StatValue },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_StatisticsParameter(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   StatisticsParameter_sequence, hf_index, ett_h248_StatisticsParameter);

  return offset;
}


static const ber_sequence_t StatisticsDescriptor_sequence_of[1] = {
  { &hf_h248_StatisticsDescriptor_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_h248_StatisticsParameter },
};

static int
dissect_h248_StatisticsDescriptor(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      StatisticsDescriptor_sequence_of, hf_index, ett_h248_StatisticsDescriptor);

  return offset;
}


static const ber_sequence_t StreamParms_sequence[] = {
  { &hf_h248_localControlDescriptor, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_LocalControlDescriptor },
  { &hf_h248_localDescriptor, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_LocalRemoteDescriptor },
  { &hf_h248_remoteDescriptor, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_LocalRemoteDescriptor },
  { &hf_h248_sPstatisticsDescriptor, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_StatisticsDescriptor },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_StreamParms(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   StreamParms_sequence, hf_index, ett_h248_StreamParms);

  return offset;
}


static const ber_sequence_t StreamDescriptor_sequence[] = {
  { &hf_h248_streamID       , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_StreamID },
  { &hf_h248_streamParms    , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_h248_StreamParms },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_StreamDescriptor(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   StreamDescriptor_sequence, hf_index, ett_h248_StreamDescriptor);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_StreamDescriptor_sequence_of[1] = {
  { &hf_h248_mediaDescriptorMultiStream_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_h248_StreamDescriptor },
};

static int
dissect_h248_SEQUENCE_OF_StreamDescriptor(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_StreamDescriptor_sequence_of, hf_index, ett_h248_SEQUENCE_OF_StreamDescriptor);

  return offset;
}


static const value_string h248_T_streams_vals[] = {
  {   0, "oneStream" },
  {   1, "multiStream" },
  { 0, NULL }
};

static const ber_choice_t T_streams_choice[] = {
  {   0, &hf_h248_mediaDescriptorOneStream, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_StreamParms },
  {   1, &hf_h248_mediaDescriptorMultiStream, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_h248_SEQUENCE_OF_StreamDescriptor },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_T_streams(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_streams_choice, hf_index, ett_h248_T_streams,
                                 NULL);

  return offset;
}


static const ber_sequence_t MediaDescriptor_sequence[] = {
  { &hf_h248_termStateDescr , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_TerminationStateDescriptor },
  { &hf_h248_streams        , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_T_streams },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_MediaDescriptor(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MediaDescriptor_sequence, hf_index, ett_h248_MediaDescriptor);

  return offset;
}


static const value_string h248_ModemType_vals[] = {
  {   0, "v18" },
  {   1, "v22" },
  {   2, "v22bis" },
  {   3, "v32" },
  {   4, "v32bis" },
  {   5, "v34" },
  {   6, "v90" },
  {   7, "v91" },
  {   8, "synchISDN" },
  { 0, NULL }
};


static int
dissect_h248_ModemType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_ModemType_sequence_of[1] = {
  { &hf_h248_mtl_item       , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_h248_ModemType },
};

static int
dissect_h248_SEQUENCE_OF_ModemType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_ModemType_sequence_of, hf_index, ett_h248_SEQUENCE_OF_ModemType);

  return offset;
}



static int
dissect_h248_OBJECT_IDENTIFIER(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_h248_INTEGER_0_255(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t H221NonStandard_sequence[] = {
  { &hf_h248_t35CountryCode1, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_INTEGER_0_255 },
  { &hf_h248_t35CountryCode2, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_h248_INTEGER_0_255 },
  { &hf_h248_t35Extension   , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_h248_INTEGER_0_255 },
  { &hf_h248_manufacturerCode, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_h248_INTEGER_0_65535 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_H221NonStandard(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   H221NonStandard_sequence, hf_index, ett_h248_H221NonStandard);

  return offset;
}



static int
dissect_h248_IA5String_SIZE_8(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const value_string h248_NonStandardIdentifier_vals[] = {
  {   0, "object" },
  {   1, "h221NonStandard" },
  {   2, "experimental" },
  { 0, NULL }
};

static const ber_choice_t NonStandardIdentifier_choice[] = {
  {   0, &hf_h248_object         , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_OBJECT_IDENTIFIER },
  {   1, &hf_h248_h221NonStandard, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_h248_H221NonStandard },
  {   2, &hf_h248_experimental   , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_h248_IA5String_SIZE_8 },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_NonStandardIdentifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 NonStandardIdentifier_choice, hf_index, ett_h248_NonStandardIdentifier,
                                 NULL);

  return offset;
}


static const ber_sequence_t NonStandardData_sequence[] = {
  { &hf_h248_nonStandardIdentifier, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_h248_NonStandardIdentifier },
  { &hf_h248_data           , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_h248_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_NonStandardData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   NonStandardData_sequence, hf_index, ett_h248_NonStandardData);

  return offset;
}


static const ber_sequence_t ModemDescriptor_sequence[] = {
  { &hf_h248_mtl            , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_SEQUENCE_OF_ModemType },
  { &hf_h248_mpl            , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_h248_SEQUENCE_OF_PropertyParm },
  { &hf_h248_nonStandardData, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_NonStandardData },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_ModemDescriptor(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ModemDescriptor_sequence, hf_index, ett_h248_ModemDescriptor);

  return offset;
}


static const value_string h248_MuxType_vals[] = {
  {   0, "h221" },
  {   1, "h223" },
  {   2, "h226" },
  {   3, "v76" },
  {   4, "nx64k" },
  { 0, NULL }
};


static int
dissect_h248_MuxType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_TerminationID_sequence_of[1] = {
  { &hf_h248_termList_item  , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_h248_TerminationID },
};

static int
dissect_h248_SEQUENCE_OF_TerminationID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_TerminationID_sequence_of, hf_index, ett_h248_SEQUENCE_OF_TerminationID);

  return offset;
}


static const ber_sequence_t MuxDescriptor_sequence[] = {
  { &hf_h248_muxType        , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_MuxType },
  { &hf_h248_termList       , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_h248_SEQUENCE_OF_TerminationID },
  { &hf_h248_nonStandardData, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_NonStandardData },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_MuxDescriptor(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MuxDescriptor_sequence, hf_index, ett_h248_MuxDescriptor);

  return offset;
}



static int
dissect_h248_RequestID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}




static int
dissect_h248_Name(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_h248_DigitMapName(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_h248_Name(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_h248_INTEGER_0_99(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t DigitMapValue_sequence[] = {
  { &hf_h248_startTimer     , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_INTEGER_0_99 },
  { &hf_h248_shortTimer     , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_INTEGER_0_99 },
  { &hf_h248_longTimer      , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_INTEGER_0_99 },
  { &hf_h248_digitMapBody   , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_h248_IA5String },
  { &hf_h248_durationTimer  , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_INTEGER_0_99 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_DigitMapValue(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DigitMapValue_sequence, hf_index, ett_h248_DigitMapValue);

  return offset;
}


static const value_string h248_EventDM_vals[] = {
  {   0, "digitMapName" },
  {   1, "digitMapValue" },
  { 0, NULL }
};

static const ber_choice_t EventDM_choice[] = {
  {   0, &hf_h248_digitMapName   , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_DigitMapName },
  {   1, &hf_h248_digitMapValue  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_h248_DigitMapValue },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_EventDM(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 EventDM_choice, hf_index, ett_h248_EventDM,
                                 NULL);

  return offset;
}



static const value_string h248_SignalType_vals[] = {
  {   0, "brief" },
  {   1, "onOff" },
  {   2, "timeOut" },
  { 0, NULL }
};


static int
dissect_h248_SignalType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static int * const NotifyCompletion_bits[] = {
  &hf_h248_NotifyCompletion_onTimeOut,
  &hf_h248_NotifyCompletion_onInterruptByEvent,
  &hf_h248_NotifyCompletion_onInterruptByNewSignalDescr,
  &hf_h248_NotifyCompletion_otherReason,
  &hf_h248_NotifyCompletion_onIteration,
  NULL
};

static int
dissect_h248_NotifyCompletion(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NotifyCompletion_bits, 5, hf_index, ett_h248_NotifyCompletion,
                                    NULL);

  return offset;
}




static const ber_sequence_t SigParamValues_sequence_of[1] = {
  { &hf_h248_SigParamValues_item, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_h248_SigParamValue },
};

static int
dissect_h248_SigParamValues(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SigParamValues_sequence_of, hf_index, ett_h248_SigParamValues);

  return offset;
}


static const value_string h248_T_extraInfo_vals[] = {
  {   0, "relation" },
  {   1, "range" },
  {   2, "sublist" },
  { 0, NULL }
};

static const ber_choice_t T_extraInfo_choice[] = {
  {   0, &hf_h248_relation       , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_Relation },
  {   1, &hf_h248_range          , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_h248_BOOLEAN },
  {   2, &hf_h248_sublist        , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_h248_BOOLEAN },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_T_extraInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_extraInfo_choice, hf_index, ett_h248_T_extraInfo,
                                 NULL);

  return offset;
}


static const ber_sequence_t SigParameter_sequence[] = {
  { &hf_h248_sigParameterName, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_SigParameterName },
  { &hf_h248_value          , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_h248_SigParamValues },
  { &hf_h248_extraInfo      , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_T_extraInfo },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_SigParameter(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
/* H248 v1 support */
	if (h248_version > 1) {
		  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SigParameter_sequence, hf_index, ett_h248_SigParameter);

} else {
	offset = dissect_h248_SigParameterV1( implicit_tag, tvb, offset, actx, tree, hf_index);
}

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_SigParameter_sequence_of[1] = {
  { &hf_h248_sigParList_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_h248_SigParameter },
};

static int
dissect_h248_SEQUENCE_OF_SigParameter(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_SigParameter_sequence_of, hf_index, ett_h248_SEQUENCE_OF_SigParameter);

  return offset;
}


static const value_string h248_SignalDirection_vals[] = {
  {   0, "internal" },
  {   1, "external" },
  {   2, "both" },
  { 0, NULL }
};


static int
dissect_h248_SignalDirection(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t Signal_sequence[] = {
  { &hf_h248_signalName     , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_SignalName },
  { &hf_h248_streamID       , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_StreamID },
  { &hf_h248_sigType        , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_SignalType },
  { &hf_h248_duration       , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_INTEGER_0_65535 },
  { &hf_h248_notifyCompletion, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_NotifyCompletion },
  { &hf_h248_keepActive     , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_BOOLEAN },
  { &hf_h248_sigParList     , BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_h248_SEQUENCE_OF_SigParameter },
  { &hf_h248_direction      , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_SignalDirection },
  { &hf_h248_requestID      , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_RequestID },
  { &hf_h248_intersigDelay  , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_INTEGER_0_65535 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_Signal(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Signal_sequence, hf_index, ett_h248_Signal);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_Signal_sequence_of[1] = {
  { &hf_h248_signalList_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_h248_Signal },
};

static int
dissect_h248_SEQUENCE_OF_Signal(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_Signal_sequence_of, hf_index, ett_h248_SEQUENCE_OF_Signal);

  return offset;
}


static const ber_sequence_t SeqSigList_sequence[] = {
  { &hf_h248_id             , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_INTEGER_0_65535 },
  { &hf_h248_signalList     , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_h248_SEQUENCE_OF_Signal },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_SeqSigList(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SeqSigList_sequence, hf_index, ett_h248_SeqSigList);

  return offset;
}


static const value_string h248_SignalRequest_vals[] = {
  {   0, "signal" },
  {   1, "seqSigList" },
  { 0, NULL }
};

static const ber_choice_t SignalRequest_choice[] = {
  {   0, &hf_h248_signal         , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_Signal },
  {   1, &hf_h248_seqSigList     , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_h248_SeqSigList },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_SignalRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 SignalRequest_choice, hf_index, ett_h248_SignalRequest,
                                 NULL);

  return offset;
}


static const ber_sequence_t SignalsDescriptor_sequence_of[1] = {
  { &hf_h248_SignalsDescriptor_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_h248_SignalRequest },
};

static int
dissect_h248_SignalsDescriptor(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SignalsDescriptor_sequence_of, hf_index, ett_h248_SignalsDescriptor);

  return offset;
}


static const ber_sequence_t RegulatedEmbeddedDescriptor_sequence[] = {
  { &hf_h248_secondEvent    , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_SecondEventsDescriptor },
  { &hf_h248_signalsDescriptor, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_SignalsDescriptor },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_RegulatedEmbeddedDescriptor(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RegulatedEmbeddedDescriptor_sequence, hf_index, ett_h248_RegulatedEmbeddedDescriptor);

  return offset;
}


static const value_string h248_NotifyBehaviour_vals[] = {
  {   0, "notifyImmediate" },
  {   1, "notifyRegulated" },
  {   2, "neverNotify" },
  { 0, NULL }
};

static const ber_choice_t NotifyBehaviour_choice[] = {
  {   0, &hf_h248_notifyImmediate, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_NULL },
  {   1, &hf_h248_notifyRegulated, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_h248_RegulatedEmbeddedDescriptor },
  {   2, &hf_h248_neverNotify    , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_h248_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_NotifyBehaviour(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 NotifyBehaviour_choice, hf_index, ett_h248_NotifyBehaviour,
                                 NULL);

  return offset;
}


static const ber_sequence_t SecondRequestedActions_sequence[] = {
  { &hf_h248_keepActive     , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_BOOLEAN },
  { &hf_h248_eventDM        , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_h248_EventDM },
  { &hf_h248_signalsDescriptor, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_SignalsDescriptor },
  { &hf_h248_notifyBehaviour, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_h248_NotifyBehaviour },
  { &hf_h248_resetEventsDescriptor, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_NULL },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_SecondRequestedActions(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SecondRequestedActions_sequence, hf_index, ett_h248_SecondRequestedActions);

  return offset;
}




static const ber_sequence_t EventParamValues_sequence_of[1] = {
  { &hf_h248_EventParamValues_item, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_h248_EventParamValue },
};

static int
dissect_h248_EventParamValues(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      EventParamValues_sequence_of, hf_index, ett_h248_EventParamValues);

  return offset;
}


static const value_string h248_EventPar_extraInfo_vals[] = {
  {   0, "relation" },
  {   1, "range" },
  {   2, "sublist" },
  { 0, NULL }
};

static const ber_choice_t EventPar_extraInfo_choice[] = {
  {   0, &hf_h248_relation       , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_Relation },
  {   1, &hf_h248_range          , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_h248_BOOLEAN },
  {   2, &hf_h248_sublist        , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_h248_BOOLEAN },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_EventPar_extraInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 EventPar_extraInfo_choice, hf_index, ett_h248_EventPar_extraInfo,
                                 NULL);

  return offset;
}


static const ber_sequence_t EventParameter_sequence[] = {
  { &hf_h248_eventParameterName, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_EventParameterName },
  { &hf_h248_eventParamValue, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_h248_EventParamValues },
  { &hf_h248_eventPar_extraInfo, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_EventPar_extraInfo },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_EventParameter(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
/* H248 v1 support */
	if (h248_version > 1) {
		  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EventParameter_sequence, hf_index, ett_h248_EventParameter);

} else {
	offset = dissect_h248_EventParameterV1( implicit_tag, tvb, offset, actx, tree, hf_index);
}

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_EventParameter_sequence_of[1] = {
  { &hf_h248_eventParList_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_h248_EventParameter },
};

static int
dissect_h248_SEQUENCE_OF_EventParameter(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_EventParameter_sequence_of, hf_index, ett_h248_SEQUENCE_OF_EventParameter);

  return offset;
}


static const ber_sequence_t SecondRequestedEvent_sequence[] = {
  { &hf_h248_pkgdName       , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_PkgdName },
  { &hf_h248_streamID       , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_StreamID },
  { &hf_h248_secondaryEventAction, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_SecondRequestedActions },
  { &hf_h248_evParList      , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_h248_SEQUENCE_OF_EventParameter },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_SecondRequestedEvent(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SecondRequestedEvent_sequence, hf_index, ett_h248_SecondRequestedEvent);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_SecondRequestedEvent_sequence_of[1] = {
  { &hf_h248_secondaryEventList_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_h248_SecondRequestedEvent },
};

static int
dissect_h248_SEQUENCE_OF_SecondRequestedEvent(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_SecondRequestedEvent_sequence_of, hf_index, ett_h248_SEQUENCE_OF_SecondRequestedEvent);

  return offset;
}


static const ber_sequence_t SecondEventsDescriptor_sequence[] = {
  { &hf_h248_requestID      , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_RequestID },
  { &hf_h248_secondaryEventList, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_h248_SEQUENCE_OF_SecondRequestedEvent },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_SecondEventsDescriptor(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  // SecondEventsDescriptor -> SecondEventsDescriptor/eventList -> SecondRequestedEvent -> SecondRequestedActions -> NotifyBehaviour -> RegulatedEmbeddedDescriptor -> SecondEventsDescriptor
  actx->pinfo->dissection_depth += 6;
  increment_dissection_depth(actx->pinfo);
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SecondEventsDescriptor_sequence, hf_index, ett_h248_SecondEventsDescriptor);

  actx->pinfo->dissection_depth -= 6;
  decrement_dissection_depth(actx->pinfo);
  return offset;
}


static const ber_sequence_t RequestedActions_sequence[] = {
  { &hf_h248_keepActive     , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_BOOLEAN },
  { &hf_h248_eventDM        , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_h248_EventDM },
  { &hf_h248_secondEvent    , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_SecondEventsDescriptor },
  { &hf_h248_signalsDescriptor, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_SignalsDescriptor },
  { &hf_h248_notifyBehaviour, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_h248_NotifyBehaviour },
  { &hf_h248_resetEventsDescriptor, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_NULL },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_RequestedActions(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RequestedActions_sequence, hf_index, ett_h248_RequestedActions);

  return offset;
}


static const ber_sequence_t RequestedEvent_sequence[] = {
  { &hf_h248_eventName      , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_EventName },
  { &hf_h248_streamID       , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_StreamID },
  { &hf_h248_eventAction    , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_RequestedActions },
  { &hf_h248_evParList      , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_h248_SEQUENCE_OF_EventParameter },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_RequestedEvent(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RequestedEvent_sequence, hf_index, ett_h248_RequestedEvent);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_RequestedEvent_sequence_of[1] = {
  { &hf_h248_eventList_item , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_h248_RequestedEvent },
};

static int
dissect_h248_SEQUENCE_OF_RequestedEvent(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_RequestedEvent_sequence_of, hf_index, ett_h248_SEQUENCE_OF_RequestedEvent);

  return offset;
}


static const ber_sequence_t EventsDescriptor_sequence[] = {
  { &hf_h248_requestID      , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_RequestID },
  { &hf_h248_eventList      , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_h248_SEQUENCE_OF_RequestedEvent },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_EventsDescriptor(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EventsDescriptor_sequence, hf_index, ett_h248_EventsDescriptor);

  return offset;
}


static const ber_sequence_t EventSpec_sequence[] = {
  { &hf_h248_eventName      , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_EventName },
  { &hf_h248_streamID       , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_StreamID },
  { &hf_h248_eventParList   , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_h248_SEQUENCE_OF_EventParameter },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_EventSpec(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EventSpec_sequence, hf_index, ett_h248_EventSpec);

  return offset;
}


static const ber_sequence_t EventBufferDescriptor_sequence_of[1] = {
  { &hf_h248_EventBufferDescriptor_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_h248_EventSpec },
};

static int
dissect_h248_EventBufferDescriptor(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      EventBufferDescriptor_sequence_of, hf_index, ett_h248_EventBufferDescriptor);

  return offset;
}


static const ber_sequence_t DigitMapDescriptor_sequence[] = {
  { &hf_h248_digitMapName   , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_DigitMapName },
  { &hf_h248_digitMapValue  , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_DigitMapValue },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_DigitMapDescriptor(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DigitMapDescriptor_sequence, hf_index, ett_h248_DigitMapDescriptor);

  return offset;
}


static int * const T_auditToken_bits[] = {
  &hf_h248_T_auditToken_muxToken,
  &hf_h248_T_auditToken_modemToken,
  &hf_h248_T_auditToken_mediaToken,
  &hf_h248_T_auditToken_eventsToken,
  &hf_h248_T_auditToken_signalsToken,
  &hf_h248_T_auditToken_digitMapToken,
  &hf_h248_T_auditToken_statsToken,
  &hf_h248_T_auditToken_observedEventsToken,
  &hf_h248_T_auditToken_packagesToken,
  &hf_h248_T_auditToken_eventBufferToken,
  NULL
};

static int
dissect_h248_T_auditToken(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    T_auditToken_bits, 10, hf_index, ett_h248_T_auditToken,
                                    NULL);

  return offset;
}


static const ber_sequence_t IndAudTerminationStateDescriptor_sequence[] = {
  { &hf_h248_indAudPropertyParms, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_SEQUENCE_OF_IndAudPropertyParm },
  { &hf_h248_eventBufferControl, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_NULL },
  { &hf_h248_iATSDServiceState, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_NULL },
  { &hf_h248_serviceStateSel, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_ServiceState },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_IndAudTerminationStateDescriptor(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   IndAudTerminationStateDescriptor_sequence, hf_index, ett_h248_IndAudTerminationStateDescriptor);

  return offset;
}


static const ber_sequence_t IndAudLocalControlDescriptor_sequence[] = {
  { &hf_h248_iALCDStreamMode, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_NULL },
  { &hf_h248_iALCDReserveValue, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_NULL },
  { &hf_h248_iALCDReserveGroup, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_NULL },
  { &hf_h248_indAudPropertyParms, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_SEQUENCE_OF_IndAudPropertyParm },
  { &hf_h248_streamModeSel  , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_StreamMode },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_IndAudLocalControlDescriptor(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   IndAudLocalControlDescriptor_sequence, hf_index, ett_h248_IndAudLocalControlDescriptor);

  return offset;
}


static const ber_sequence_t IndAudPropertyGroup_sequence_of[1] = {
  { &hf_h248_IndAudPropertyGroup_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_h248_IndAudPropertyParm },
};

static int
dissect_h248_IndAudPropertyGroup(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      IndAudPropertyGroup_sequence_of, hf_index, ett_h248_IndAudPropertyGroup);

  return offset;
}


static const ber_sequence_t IndAudLocalRemoteDescriptor_sequence[] = {
  { &hf_h248_propGroupID    , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_INTEGER_0_65535 },
  { &hf_h248_iAPropertyGroup, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_h248_IndAudPropertyGroup },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_IndAudLocalRemoteDescriptor(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   IndAudLocalRemoteDescriptor_sequence, hf_index, ett_h248_IndAudLocalRemoteDescriptor);

  return offset;
}


static const ber_sequence_t IndAudStatisticsDescriptor_sequence[] = {
  { &hf_h248_iAStatName     , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_PkgdName },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_IndAudStatisticsDescriptor(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   IndAudStatisticsDescriptor_sequence, hf_index, ett_h248_IndAudStatisticsDescriptor);

  return offset;
}


static const ber_sequence_t IndAudStreamParms_sequence[] = {
  { &hf_h248_iASPLocalControlDescriptor, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_IndAudLocalControlDescriptor },
  { &hf_h248_iASPLocalDescriptor, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_IndAudLocalRemoteDescriptor },
  { &hf_h248_iASPRemoteDescriptor, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_IndAudLocalRemoteDescriptor },
  { &hf_h248_statisticsDescriptor, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_IndAudStatisticsDescriptor },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_IndAudStreamParms(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   IndAudStreamParms_sequence, hf_index, ett_h248_IndAudStreamParms);

  return offset;
}


static const ber_sequence_t IndAudStreamDescriptor_sequence[] = {
  { &hf_h248_streamID       , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_StreamID },
  { &hf_h248_indAudStreamParms, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_h248_IndAudStreamParms },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_IndAudStreamDescriptor(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   IndAudStreamDescriptor_sequence, hf_index, ett_h248_IndAudStreamDescriptor);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_IndAudStreamDescriptor_sequence_of[1] = {
  { &hf_h248_multiStream_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_h248_IndAudStreamDescriptor },
};

static int
dissect_h248_SEQUENCE_OF_IndAudStreamDescriptor(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_IndAudStreamDescriptor_sequence_of, hf_index, ett_h248_SEQUENCE_OF_IndAudStreamDescriptor);

  return offset;
}


static const value_string h248_IndAudMediaDescriptorStreams_vals[] = {
  {   0, "oneStream" },
  {   1, "multiStream" },
  { 0, NULL }
};

static const ber_choice_t IndAudMediaDescriptorStreams_choice[] = {
  {   0, &hf_h248_oneStream      , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_IndAudStreamParms },
  {   1, &hf_h248_multiStream    , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_h248_SEQUENCE_OF_IndAudStreamDescriptor },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_IndAudMediaDescriptorStreams(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 IndAudMediaDescriptorStreams_choice, hf_index, ett_h248_IndAudMediaDescriptorStreams,
                                 NULL);

  return offset;
}


static const ber_sequence_t IndAudMediaDescriptor_sequence[] = {
  { &hf_h248_indAudTerminationStateDescriptor, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_IndAudTerminationStateDescriptor },
  { &hf_h248_indAudMediaDescriptorStreams, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_IndAudMediaDescriptorStreams },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_IndAudMediaDescriptor(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   IndAudMediaDescriptor_sequence, hf_index, ett_h248_IndAudMediaDescriptor);

  return offset;
}


static const ber_sequence_t IndAudEventsDescriptor_sequence[] = {
  { &hf_h248_requestID      , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_RequestID },
  { &hf_h248_iAEDPkgdName   , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_h248_PkgdName },
  { &hf_h248_streamID       , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_StreamID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_IndAudEventsDescriptor(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   IndAudEventsDescriptor_sequence, hf_index, ett_h248_IndAudEventsDescriptor);

  return offset;
}


static const ber_sequence_t IndAudEventBufferDescriptor_sequence[] = {
  { &hf_h248_iAEBDEventName , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_PkgdName },
  { &hf_h248_streamID       , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_StreamID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_IndAudEventBufferDescriptor(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   IndAudEventBufferDescriptor_sequence, hf_index, ett_h248_IndAudEventBufferDescriptor);

  return offset;
}


static const ber_sequence_t IndAudSignal_sequence[] = {
  { &hf_h248_iASignalName   , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_PkgdName },
  { &hf_h248_streamID       , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_StreamID },
  { &hf_h248_signalRequestID, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_RequestID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_IndAudSignal(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   IndAudSignal_sequence, hf_index, ett_h248_IndAudSignal);

  return offset;
}


static const ber_sequence_t IndAudSeqSigList_sequence[] = {
  { &hf_h248_id             , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_INTEGER_0_65535 },
  { &hf_h248_iASignalList   , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_IndAudSignal },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_IndAudSeqSigList(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   IndAudSeqSigList_sequence, hf_index, ett_h248_IndAudSeqSigList);

  return offset;
}


static const value_string h248_IndAudSignalsDescriptor_vals[] = {
  {   0, "signal" },
  {   1, "seqSigList" },
  { 0, NULL }
};

static const ber_choice_t IndAudSignalsDescriptor_choice[] = {
  {   0, &hf_h248_indAudSignal   , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_IndAudSignal },
  {   1, &hf_h248_indAudSeqSigList, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_h248_IndAudSeqSigList },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_IndAudSignalsDescriptor(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 IndAudSignalsDescriptor_choice, hf_index, ett_h248_IndAudSignalsDescriptor,
                                 NULL);

  return offset;
}


static const ber_sequence_t IndAudDigitMapDescriptor_sequence[] = {
  { &hf_h248_digitMapName   , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_DigitMapName },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_IndAudDigitMapDescriptor(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   IndAudDigitMapDescriptor_sequence, hf_index, ett_h248_IndAudDigitMapDescriptor);

  return offset;
}


static const ber_sequence_t IndAudPackagesDescriptor_sequence[] = {
  { &hf_h248_packageName    , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_Name },
  { &hf_h248_packageVersion , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_h248_INTEGER_0_99 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_IndAudPackagesDescriptor(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   IndAudPackagesDescriptor_sequence, hf_index, ett_h248_IndAudPackagesDescriptor);

  return offset;
}


static const value_string h248_IndAuditParameter_vals[] = {
  {   0, "indaudmediaDescriptor" },
  {   1, "indaudeventsDescriptor" },
  {   2, "indaudeventBufferDescriptor" },
  {   3, "indaudsignalsDescriptor" },
  {   4, "indauddigitMapDescriptor" },
  {   5, "indaudstatisticsDescriptor" },
  {   6, "indaudpackagesDescriptor" },
  { 0, NULL }
};

static const ber_choice_t IndAuditParameter_choice[] = {
  {   0, &hf_h248_indaudmediaDescriptor, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_IndAudMediaDescriptor },
  {   1, &hf_h248_indaudeventsDescriptor, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_h248_IndAudEventsDescriptor },
  {   2, &hf_h248_indaudeventBufferDescriptor, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_h248_IndAudEventBufferDescriptor },
  {   3, &hf_h248_indaudsignalsDescriptor, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_h248_IndAudSignalsDescriptor },
  {   4, &hf_h248_indauddigitMapDescriptor, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_h248_IndAudDigitMapDescriptor },
  {   5, &hf_h248_indaudstatisticsDescriptor, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_h248_IndAudStatisticsDescriptor },
  {   6, &hf_h248_indaudpackagesDescriptor, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_h248_IndAudPackagesDescriptor },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_IndAuditParameter(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 IndAuditParameter_choice, hf_index, ett_h248_IndAuditParameter,
                                 NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_IndAuditParameter_sequence_of[1] = {
  { &hf_h248_auditPropertyToken_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_h248_IndAuditParameter },
};

static int
dissect_h248_SEQUENCE_OF_IndAuditParameter(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_IndAuditParameter_sequence_of, hf_index, ett_h248_SEQUENCE_OF_IndAuditParameter);

  return offset;
}


static const ber_sequence_t AuditDescriptor_sequence[] = {
  { &hf_h248_auditToken     , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_T_auditToken },
  { &hf_h248_auditPropertyToken, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_SEQUENCE_OF_IndAuditParameter },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_AuditDescriptor(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AuditDescriptor_sequence, hf_index, ett_h248_AuditDescriptor);

  return offset;
}


static const value_string h248_AmmDescriptor_vals[] = {
  {   0, "mediaDescriptor" },
  {   1, "modemDescriptor" },
  {   2, "muxDescriptor" },
  {   3, "eventsDescriptor" },
  {   4, "eventBufferDescriptor" },
  {   5, "signalsDescriptor" },
  {   6, "digitMapDescriptor" },
  {   7, "auditDescriptor" },
  {   8, "statisticsDescriptor" },
  { 0, NULL }
};

static const ber_choice_t AmmDescriptor_choice[] = {
  {   0, &hf_h248_mediaDescriptor, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_MediaDescriptor },
  {   1, &hf_h248_modemDescriptor, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_h248_ModemDescriptor },
  {   2, &hf_h248_muxDescriptor  , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_h248_MuxDescriptor },
  {   3, &hf_h248_eventsDescriptor, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_h248_EventsDescriptor },
  {   4, &hf_h248_eventBufferDescriptor, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_h248_EventBufferDescriptor },
  {   5, &hf_h248_signalsDescriptor, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_h248_SignalsDescriptor },
  {   6, &hf_h248_digitMapDescriptor, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_h248_DigitMapDescriptor },
  {   7, &hf_h248_auditDescriptor, BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_h248_AuditDescriptor },
  {   8, &hf_h248_aDstatisticsDescriptor, BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_h248_StatisticsDescriptor },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_AmmDescriptor(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 AmmDescriptor_choice, hf_index, ett_h248_AmmDescriptor,
                                 NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_AmmDescriptor_sequence_of[1] = {
  { &hf_h248_descriptors_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_h248_AmmDescriptor },
};

static int
dissect_h248_SEQUENCE_OF_AmmDescriptor(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_AmmDescriptor_sequence_of, hf_index, ett_h248_SEQUENCE_OF_AmmDescriptor);

  return offset;
}


static const ber_sequence_t AmmRequest_sequence[] = {
  { &hf_h248_terminationIDList, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_TerminationIDList },
  { &hf_h248_descriptors    , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_h248_SEQUENCE_OF_AmmDescriptor },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_AmmRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AmmRequest_sequence, hf_index, ett_h248_AmmRequest);

  return offset;
}



static int
dissect_h248_T_addReq(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
	  curr_info.cmd = gcp_cmd(curr_info.msg,curr_info.trx,curr_info.ctx,GCP_CMD_ADD_REQ,offset,actx->pinfo,keep_persistent_data);
      H248_TAP();
  offset = dissect_h248_AmmRequest(implicit_tag, tvb, offset, actx, tree, hf_index);

      curr_info.cmd = NULL;
  return offset;
}



static int
dissect_h248_T_moveReq(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
	  curr_info.cmd = gcp_cmd(curr_info.msg,curr_info.trx,curr_info.ctx,GCP_CMD_MOVE_REQ,offset,actx->pinfo,keep_persistent_data);
      H248_TAP();

  offset = dissect_h248_AmmRequest(implicit_tag, tvb, offset, actx, tree, hf_index);

      curr_info.cmd = NULL;
  return offset;
}



static int
dissect_h248_T_modReq(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
	  curr_info.cmd = gcp_cmd(curr_info.msg,curr_info.trx,curr_info.ctx,GCP_CMD_MOD_REQ,offset,actx->pinfo,keep_persistent_data);
      H248_TAP();
  offset = dissect_h248_AmmRequest(implicit_tag, tvb, offset, actx, tree, hf_index);

      curr_info.cmd = NULL;
  return offset;
}


static const ber_sequence_t SubtractRequest_sequence[] = {
  { &hf_h248_terminationIDList, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_TerminationIDList },
  { &hf_h248_auditDescriptor, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_AuditDescriptor },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_SubtractRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SubtractRequest_sequence, hf_index, ett_h248_SubtractRequest);

  return offset;
}



static int
dissect_h248_T_subtractReq(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
	  curr_info.cmd = gcp_cmd(curr_info.msg,curr_info.trx,curr_info.ctx,GCP_CMD_SUB_REQ,offset,actx->pinfo,keep_persistent_data);
      H248_TAP();
  offset = dissect_h248_SubtractRequest(implicit_tag, tvb, offset, actx, tree, hf_index);

      curr_info.cmd = NULL;
  return offset;
}


static const ber_sequence_t AuditRequest_sequence[] = {
  { &hf_h248_terminationID  , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_TerminationID },
  { &hf_h248_auditDescriptor, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_h248_AuditDescriptor },
  { &hf_h248_terminationIDList, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_TerminationIDList },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_AuditRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AuditRequest_sequence, hf_index, ett_h248_AuditRequest);

  return offset;
}



static int
dissect_h248_T_auditCapRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
	  curr_info.cmd = gcp_cmd(curr_info.msg,curr_info.trx,curr_info.ctx,GCP_CMD_AUDITCAP_REQ,offset,actx->pinfo,keep_persistent_data);
      H248_TAP();
  offset = dissect_h248_AuditRequest(implicit_tag, tvb, offset, actx, tree, hf_index);

      curr_info.cmd = NULL;
  return offset;
}



static int
dissect_h248_T_auditValueRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
	  curr_info.cmd = gcp_cmd(curr_info.msg,curr_info.trx,curr_info.ctx,GCP_CMD_AUDITVAL_REQ,offset,actx->pinfo,keep_persistent_data);
      H248_TAP();
  offset = dissect_h248_AuditRequest(implicit_tag, tvb, offset, actx, tree, hf_index);

      curr_info.cmd = NULL;
  return offset;
}


static const ber_sequence_t TimeNotation_sequence[] = {
  { &hf_h248_date           , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_IA5String_SIZE_8 },
  { &hf_h248_time           , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_h248_IA5String_SIZE_8 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_TimeNotation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TimeNotation_sequence, hf_index, ett_h248_TimeNotation);

  return offset;
}


static const ber_sequence_t ObservedEvent_sequence[] = {
  { &hf_h248_eventName      , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_EventName },
  { &hf_h248_streamID       , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_StreamID },
  { &hf_h248_eventParList   , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_h248_SEQUENCE_OF_EventParameter },
  { &hf_h248_timeNotation   , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_TimeNotation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_ObservedEvent(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ObservedEvent_sequence, hf_index, ett_h248_ObservedEvent);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_ObservedEvent_sequence_of[1] = {
  { &hf_h248_observedEventLst_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_h248_ObservedEvent },
};

static int
dissect_h248_SEQUENCE_OF_ObservedEvent(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_ObservedEvent_sequence_of, hf_index, ett_h248_SEQUENCE_OF_ObservedEvent);

  return offset;
}


static const ber_sequence_t ObservedEventsDescriptor_sequence[] = {
  { &hf_h248_requestId      , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_RequestID },
  { &hf_h248_observedEventLst, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_h248_SEQUENCE_OF_ObservedEvent },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_ObservedEventsDescriptor(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ObservedEventsDescriptor_sequence, hf_index, ett_h248_ObservedEventsDescriptor);

  return offset;
}


static const ber_sequence_t NotifyRequest_sequence[] = {
  { &hf_h248_terminationIDList, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_TerminationIDList },
  { &hf_h248_observedEventsDescriptor, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_h248_ObservedEventsDescriptor },
  { &hf_h248_errorDescriptor, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_ErrorDescriptor },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_NotifyRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   NotifyRequest_sequence, hf_index, ett_h248_NotifyRequest);

  return offset;
}



static int
dissect_h248_T_notifyReq(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
	  curr_info.cmd = gcp_cmd(curr_info.msg,curr_info.trx,curr_info.ctx,GCP_CMD_NOTIFY_REQ,offset,actx->pinfo,keep_persistent_data);
      H248_TAP();
  offset = dissect_h248_NotifyRequest(implicit_tag, tvb, offset, actx, tree, hf_index);

      curr_info.cmd = NULL;
  return offset;
}


static const value_string h248_ServiceChangeMethod_vals[] = {
  {   0, "failover" },
  {   1, "forced" },
  {   2, "graceful" },
  {   3, "restart" },
  {   4, "disconnected" },
  {   5, "handOff" },
  { 0, NULL }
};


static int
dissect_h248_ServiceChangeMethod(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string h248_ServiceChangeAddress_vals[] = {
  {   0, "portNumber" },
  {   1, "ip4Address" },
  {   2, "ip6Address" },
  {   3, "domainName" },
  {   4, "deviceName" },
  {   5, "mtpAddress" },
  { 0, NULL }
};

static const ber_choice_t ServiceChangeAddress_choice[] = {
  {   0, &hf_h248_portNumber     , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_INTEGER_0_65535 },
  {   1, &hf_h248_ip4Address     , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_h248_IP4Address },
  {   2, &hf_h248_ip6Address     , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_h248_IP6Address },
  {   3, &hf_h248_domainName     , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_h248_DomainName },
  {   4, &hf_h248_deviceName     , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_h248_PathName },
  {   5, &hf_h248_mtpAddress     , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_h248_MtpAddress },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_ServiceChangeAddress(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ServiceChangeAddress_choice, hf_index, ett_h248_ServiceChangeAddress,
                                 NULL);

  return offset;
}



static int
dissect_h248_IA5String_SIZE_1_67(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t ServiceChangeProfile_sequence[] = {
  { &hf_h248_profileName    , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_IA5String_SIZE_1_67 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_ServiceChangeProfile(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ServiceChangeProfile_sequence, hf_index, ett_h248_ServiceChangeProfile);

  return offset;
}



static int
dissect_h248_SCreasonValueOctetStr(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
 tvbuff_t	*parameter_tvb;
   offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &parameter_tvb);


 if (!parameter_tvb)
	return offset;

 dissect_h248_ServiceChangeReasonStr(false, parameter_tvb, 0, actx, tree, hf_h248_serviceChangeReasonStr);

  return offset;
}


static const ber_sequence_t SCreasonValue_sequence_of[1] = {
  { &hf_h248_SCreasonValue_item, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_h248_SCreasonValueOctetStr },
};

static int
dissect_h248_SCreasonValue(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SCreasonValue_sequence_of, hf_index, ett_h248_SCreasonValue);

  return offset;
}



static int
dissect_h248_INTEGER_0_4294967295(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t ServiceChangeParm_sequence[] = {
  { &hf_h248_serviceChangeMethod, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_ServiceChangeMethod },
  { &hf_h248_serviceChangeAddress, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_h248_ServiceChangeAddress },
  { &hf_h248_serviceChangeVersion, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_INTEGER_0_99 },
  { &hf_h248_serviceChangeProfile, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_ServiceChangeProfile },
  { &hf_h248_serviceChangeReason, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_h248_SCreasonValue },
  { &hf_h248_serviceChangeDelay, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_INTEGER_0_4294967295 },
  { &hf_h248_serviceChangeMgcId, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_h248_MId },
  { &hf_h248_timeStamp      , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_TimeNotation },
  { &hf_h248_nonStandardData, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_NonStandardData },
  { &hf_h248_serviceChangeInfo, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_AuditDescriptor },
  { &hf_h248_serviceChangeIncompleteFlag, BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_NULL },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_ServiceChangeParm(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ServiceChangeParm_sequence, hf_index, ett_h248_ServiceChangeParm);

  return offset;
}


static const ber_sequence_t ServiceChangeRequest_sequence[] = {
  { &hf_h248_terminationIDList, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_TerminationIDList },
  { &hf_h248_serviceChangeParms, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_h248_ServiceChangeParm },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_ServiceChangeRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
      curr_info.cmd = gcp_cmd(curr_info.msg,curr_info.trx,curr_info.ctx,GCP_CMD_SVCCHG_REQ,offset,actx->pinfo,keep_persistent_data);
      H248_TAP();
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ServiceChangeRequest_sequence, hf_index, ett_h248_ServiceChangeRequest);

      curr_info.cmd = NULL;
  return offset;
}


static const value_string h248_Command_vals[] = {
  {   0, "addReq" },
  {   1, "moveReq" },
  {   2, "modReq" },
  {   3, "subtractReq" },
  {   4, "auditCapRequest" },
  {   5, "auditValueRequest" },
  {   6, "notifyReq" },
  {   7, "serviceChangeReq" },
  { 0, NULL }
};

static const ber_choice_t Command_choice[] = {
  {   0, &hf_h248_addReq         , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_T_addReq },
  {   1, &hf_h248_moveReq        , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_h248_T_moveReq },
  {   2, &hf_h248_modReq         , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_h248_T_modReq },
  {   3, &hf_h248_subtractReq    , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_h248_T_subtractReq },
  {   4, &hf_h248_auditCapRequest, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_h248_T_auditCapRequest },
  {   5, &hf_h248_auditValueRequest, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_h248_T_auditValueRequest },
  {   6, &hf_h248_notifyReq      , BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_h248_T_notifyReq },
  {   7, &hf_h248_serviceChangeReq, BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_h248_ServiceChangeRequest },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_Command(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Command_choice, hf_index, ett_h248_Command,
                                 NULL);

  return offset;
}


static const ber_sequence_t CommandRequest_sequence[] = {
  { &hf_h248_command        , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_h248_Command },
  { &hf_h248_optional       , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_NULL },
  { &hf_h248_wildcardReturn , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_NULL },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_CommandRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CommandRequest_sequence, hf_index, ett_h248_CommandRequest);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_CommandRequest_sequence_of[1] = {
  { &hf_h248_commandRequests_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_h248_CommandRequest },
};

static int
dissect_h248_SEQUENCE_OF_CommandRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_CommandRequest_sequence_of, hf_index, ett_h248_SEQUENCE_OF_CommandRequest);

  return offset;
}


static const ber_sequence_t ActionRequest_sequence[] = {
  { &hf_h248_contextId      , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_ContextId },
  { &hf_h248_contextRequest , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_ContextRequest },
  { &hf_h248_contextAttrAuditReq, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_T_contextAttrAuditReq },
  { &hf_h248_commandRequests, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_h248_SEQUENCE_OF_CommandRequest },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_ActionRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ActionRequest_sequence, hf_index, ett_h248_ActionRequest);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_ActionRequest_sequence_of[1] = {
  { &hf_h248_actions_item   , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_h248_ActionRequest },
};

static int
dissect_h248_SEQUENCE_OF_ActionRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_ActionRequest_sequence_of, hf_index, ett_h248_SEQUENCE_OF_ActionRequest);

  return offset;
}


static const ber_sequence_t TransactionRequest_sequence[] = {
  { &hf_h248_transactionId  , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_T_transactionId },
  { &hf_h248_actions        , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_h248_SEQUENCE_OF_ActionRequest },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_TransactionRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TransactionRequest_sequence, hf_index, ett_h248_TransactionRequest);

  return offset;
}



static int
dissect_h248_T_tpend_transactionId(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    uint32_t trx_id = 0;
	offset = dissect_h248_trx_id(implicit_tag, actx->pinfo, tree, tvb, offset, &trx_id);
    curr_info.trx = gcp_trx(curr_info.msg, trx_id, GCP_TRX_PENDING, actx->pinfo, keep_persistent_data);
    error_code = 0;


  return offset;
}


static const ber_sequence_t TransactionPending_sequence[] = {
  { &hf_h248_tpend_transactionId, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_T_tpend_transactionId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_TransactionPending(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TransactionPending_sequence, hf_index, ett_h248_TransactionPending);

  return offset;
}



static int
dissect_h248_T_trep_transactionId(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    uint32_t trx_id = 0;
	offset = dissect_h248_trx_id(implicit_tag, actx->pinfo, tree, tvb, offset, &trx_id);
    curr_info.trx = gcp_trx(curr_info.msg, trx_id, GCP_TRX_REPLY, actx->pinfo, keep_persistent_data);
    error_code = 0;


  return offset;
}


static const ber_sequence_t PackagesItem_sequence[] = {
  { &hf_h248_packageName    , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_Name },
  { &hf_h248_packageVersion , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_h248_INTEGER_0_99 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_PackagesItem(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PackagesItem_sequence, hf_index, ett_h248_PackagesItem);

  return offset;
}


static const ber_sequence_t PackagesDescriptor_sequence_of[1] = {
  { &hf_h248_PackagesDescriptor_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_h248_PackagesItem },
};

static int
dissect_h248_PackagesDescriptor(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      PackagesDescriptor_sequence_of, hf_index, ett_h248_PackagesDescriptor);

  return offset;
}


static const value_string h248_AuditReturnParameter_vals[] = {
  {   0, "errorDescriptor" },
  {   1, "mediaDescriptor" },
  {   2, "modemDescriptor" },
  {   3, "muxDescriptor" },
  {   4, "eventsDescriptor" },
  {   5, "eventBufferDescriptor" },
  {   6, "signalsDescriptor" },
  {   7, "digitMapDescriptor" },
  {   8, "observedEventsDescriptor" },
  {   9, "statisticsDescriptor" },
  {  10, "packagesDescriptor" },
  {  11, "emptyDescriptors" },
  { 0, NULL }
};

static const ber_choice_t AuditReturnParameter_choice[] = {
  {   0, &hf_h248_errorDescriptor, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_ErrorDescriptor },
  {   1, &hf_h248_mediaDescriptor, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_h248_MediaDescriptor },
  {   2, &hf_h248_modemDescriptor, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_h248_ModemDescriptor },
  {   3, &hf_h248_muxDescriptor  , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_h248_MuxDescriptor },
  {   4, &hf_h248_eventsDescriptor, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_h248_EventsDescriptor },
  {   5, &hf_h248_eventBufferDescriptor, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_h248_EventBufferDescriptor },
  {   6, &hf_h248_signalsDescriptor, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_h248_SignalsDescriptor },
  {   7, &hf_h248_digitMapDescriptor, BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_h248_DigitMapDescriptor },
  {   8, &hf_h248_observedEventsDescriptor, BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_h248_ObservedEventsDescriptor },
  {   9, &hf_h248_aRPstatisticsDescriptor, BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_h248_StatisticsDescriptor },
  {  10, &hf_h248_packagesDescriptor, BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_h248_PackagesDescriptor },
  {  11, &hf_h248_emptyDescriptors, BER_CLASS_CON, 11, BER_FLAGS_IMPLTAG, dissect_h248_AuditDescriptor },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_AuditReturnParameter(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 AuditReturnParameter_choice, hf_index, ett_h248_AuditReturnParameter,
                                 NULL);

  return offset;
}


static const ber_sequence_t TerminationAudit_sequence_of[1] = {
  { &hf_h248_TerminationAudit_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_h248_AuditReturnParameter },
};

static int
dissect_h248_TerminationAudit(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      TerminationAudit_sequence_of, hf_index, ett_h248_TerminationAudit);

  return offset;
}


static const ber_sequence_t AmmsReply_sequence[] = {
  { &hf_h248_terminationIDList, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_TerminationIDList },
  { &hf_h248_terminationAudit, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_TerminationAudit },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_AmmsReply(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AmmsReply_sequence, hf_index, ett_h248_AmmsReply);

  return offset;
}



static int
dissect_h248_T_addReply(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
      curr_info.cmd = gcp_cmd(curr_info.msg,curr_info.trx,curr_info.ctx,GCP_CMD_ADD_REPLY,offset,actx->pinfo,keep_persistent_data);
      H248_TAP();
  offset = dissect_h248_AmmsReply(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_h248_T_moveReply(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
      curr_info.cmd = gcp_cmd(curr_info.msg,curr_info.trx,curr_info.ctx,GCP_CMD_MOVE_REPLY,offset,actx->pinfo,keep_persistent_data);
      H248_TAP();
  offset = dissect_h248_AmmsReply(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_h248_T_modReply(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
      curr_info.cmd = gcp_cmd(curr_info.msg,curr_info.trx,curr_info.ctx,GCP_CMD_MOD_REPLY,offset,actx->pinfo,keep_persistent_data);
      H248_TAP();
  offset = dissect_h248_AmmsReply(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_h248_T_subtractReply(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
      curr_info.cmd = gcp_cmd(curr_info.msg,curr_info.trx,curr_info.ctx,GCP_CMD_SUB_REPLY,offset,actx->pinfo,keep_persistent_data);
      H248_TAP();
  offset = dissect_h248_AmmsReply(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t AuditResult_sequence[] = {
  { &hf_h248_terminationID  , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_TerminationID },
  { &hf_h248_terminationAuditResult, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_h248_TerminationAudit },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_AuditResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AuditResult_sequence, hf_index, ett_h248_AuditResult);

  return offset;
}


static const ber_sequence_t TermListAuditResult_sequence[] = {
  { &hf_h248_terminationIDList, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_TerminationIDList },
  { &hf_h248_terminationAuditResult, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_h248_TerminationAudit },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_TermListAuditResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TermListAuditResult_sequence, hf_index, ett_h248_TermListAuditResult);

  return offset;
}


static const value_string h248_AuditReply_vals[] = {
  {   0, "contextAuditResult" },
  {   1, "error" },
  {   2, "auditResult" },
  {   3, "auditResultTermList" },
  { 0, NULL }
};

static const ber_choice_t AuditReply_choice[] = {
  {   0, &hf_h248_contextAuditResult, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_TerminationIDList },
  {   1, &hf_h248_error          , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_h248_ErrorDescriptor },
  {   2, &hf_h248_auditResult    , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_h248_AuditResult },
  {   3, &hf_h248_auditResultTermList, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_h248_TermListAuditResult },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_AuditReply(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 AuditReply_choice, hf_index, ett_h248_AuditReply,
                                 NULL);

  return offset;
}



static int
dissect_h248_T_auditCapReply(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
      curr_info.cmd = gcp_cmd(curr_info.msg,curr_info.trx,curr_info.ctx,GCP_CMD_AUDITCAP_REPLY,offset,actx->pinfo,keep_persistent_data);
      H248_TAP();
/* h248v1 support */
	if(h248_version > 1) {
		  offset = dissect_h248_AuditReply(implicit_tag, tvb, offset, actx, tree, hf_index);

} else {
	/* call V1 of the dissector */
	offset = dissect_h248_AuditReplyV1(implicit_tag, tvb, offset, actx, tree, hf_index);
}

  return offset;
}



static int
dissect_h248_T_auditValueReply(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
      curr_info.cmd = gcp_cmd(curr_info.msg,curr_info.trx,curr_info.ctx,GCP_CMD_AUDITVAL_REPLY,offset,actx->pinfo,keep_persistent_data);
      H248_TAP();
/* h248v1 support */
	if(h248_version > 1) {
		  offset = dissect_h248_AuditReply(implicit_tag, tvb, offset, actx, tree, hf_index);

} else {
	/* call V1 of the dissector */
	offset = dissect_h248_AuditReplyV1(implicit_tag, tvb, offset, actx, tree, hf_index);
}

  return offset;
}


static const ber_sequence_t NotifyReply_sequence[] = {
  { &hf_h248_terminationIDList, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_TerminationIDList },
  { &hf_h248_errorDescriptor, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_ErrorDescriptor },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_NotifyReply(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   NotifyReply_sequence, hf_index, ett_h248_NotifyReply);

  return offset;
}



static int
dissect_h248_T_notifyReply(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
      curr_info.cmd = gcp_cmd(curr_info.msg,curr_info.trx,curr_info.ctx,GCP_CMD_NOTIFY_REPLY,offset,actx->pinfo,keep_persistent_data);
      H248_TAP();
  offset = dissect_h248_NotifyReply(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t ServiceChangeResParm_sequence[] = {
  { &hf_h248_serviceChangeMgcId, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_h248_MId },
  { &hf_h248_serviceChangeAddress, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_h248_ServiceChangeAddress },
  { &hf_h248_serviceChangeVersion, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_INTEGER_0_99 },
  { &hf_h248_serviceChangeProfile, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_ServiceChangeProfile },
  { &hf_h248_timestamp      , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_TimeNotation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_ServiceChangeResParm(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ServiceChangeResParm_sequence, hf_index, ett_h248_ServiceChangeResParm);

  return offset;
}


static const value_string h248_ServiceChangeResult_vals[] = {
  {   0, "errorDescriptor" },
  {   1, "serviceChangeResParms" },
  { 0, NULL }
};

static const ber_choice_t ServiceChangeResult_choice[] = {
  {   0, &hf_h248_errorDescriptor, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_ErrorDescriptor },
  {   1, &hf_h248_serviceChangeResParms, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_h248_ServiceChangeResParm },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_ServiceChangeResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ServiceChangeResult_choice, hf_index, ett_h248_ServiceChangeResult,
                                 NULL);

  return offset;
}


static const ber_sequence_t ServiceChangeReply_sequence[] = {
  { &hf_h248_terminationIDList, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_TerminationIDList },
  { &hf_h248_serviceChangeResult, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_h248_ServiceChangeResult },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_ServiceChangeReply(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
      curr_info.cmd = gcp_cmd(curr_info.msg,curr_info.trx,curr_info.ctx,GCP_CMD_SVCCHG_REPLY,offset,actx->pinfo,keep_persistent_data);
      H248_TAP();
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ServiceChangeReply_sequence, hf_index, ett_h248_ServiceChangeReply);

  return offset;
}


static const value_string h248_CommandReply_vals[] = {
  {   0, "addReply" },
  {   1, "moveReply" },
  {   2, "modReply" },
  {   3, "subtractReply" },
  {   4, "auditCapReply" },
  {   5, "auditValueReply" },
  {   6, "notifyReply" },
  {   7, "serviceChangeReply" },
  { 0, NULL }
};

static const ber_choice_t CommandReply_choice[] = {
  {   0, &hf_h248_addReply       , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_T_addReply },
  {   1, &hf_h248_moveReply      , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_h248_T_moveReply },
  {   2, &hf_h248_modReply       , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_h248_T_modReply },
  {   3, &hf_h248_subtractReply  , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_h248_T_subtractReply },
  {   4, &hf_h248_auditCapReply  , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_h248_T_auditCapReply },
  {   5, &hf_h248_auditValueReply, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_h248_T_auditValueReply },
  {   6, &hf_h248_notifyReply    , BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_h248_T_notifyReply },
  {   7, &hf_h248_serviceChangeReply, BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_h248_ServiceChangeReply },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_CommandReply(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 CommandReply_choice, hf_index, ett_h248_CommandReply,
                                 NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_CommandReply_sequence_of[1] = {
  { &hf_h248_commandReply_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_h248_CommandReply },
};

static int
dissect_h248_SEQUENCE_OF_CommandReply(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_CommandReply_sequence_of, hf_index, ett_h248_SEQUENCE_OF_CommandReply);

  return offset;
}


static const ber_sequence_t ActionReply_sequence[] = {
  { &hf_h248_contextId      , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_ContextId },
  { &hf_h248_errorDescriptor, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_ErrorDescriptor },
  { &hf_h248_contextReply   , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_ContextRequest },
  { &hf_h248_commandReply   , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_h248_SEQUENCE_OF_CommandReply },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_ActionReply(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ActionReply_sequence, hf_index, ett_h248_ActionReply);

    if (!curr_info.cmd) {
	  curr_info.cmd = gcp_cmd(curr_info.msg,curr_info.trx,curr_info.ctx,GCP_CMD_REPLY,offset,actx->pinfo,keep_persistent_data);
      H248_TAP();
	}
  return offset;
}


static const ber_sequence_t SEQUENCE_OF_ActionReply_sequence_of[1] = {
  { &hf_h248_actionReplies_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_h248_ActionReply },
};

static int
dissect_h248_SEQUENCE_OF_ActionReply(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_ActionReply_sequence_of, hf_index, ett_h248_SEQUENCE_OF_ActionReply);

  return offset;
}


static const value_string h248_T_transactionResult_vals[] = {
  {   0, "transactionError" },
  {   1, "actionReplies" },
  { 0, NULL }
};

static const ber_choice_t T_transactionResult_choice[] = {
  {   0, &hf_h248_transactionError, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_ErrorDescriptor },
  {   1, &hf_h248_actionReplies  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_h248_SEQUENCE_OF_ActionReply },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_T_transactionResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_transactionResult_choice, hf_index, ett_h248_T_transactionResult,
                                 NULL);

  return offset;
}



static int
dissect_h248_SegmentNumber(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t TransactionReply_sequence[] = {
  { &hf_h248_trep_transactionId, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_T_trep_transactionId },
  { &hf_h248_immAckRequired , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_NULL },
  { &hf_h248_transactionResult, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_h248_T_transactionResult },
  { &hf_h248_segmentNumber  , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_SegmentNumber },
  { &hf_h248_segmentationComplete, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_NULL },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_TransactionReply(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TransactionReply_sequence, hf_index, ett_h248_TransactionReply);

  return offset;
}


static const ber_sequence_t TransactionAck_sequence[] = {
  { &hf_h248_firstAck       , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_TransactionId },
  { &hf_h248_lastAck        , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_TransactionId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_TransactionAck(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TransactionAck_sequence, hf_index, ett_h248_TransactionAck);

  return offset;
}


static const ber_sequence_t TransactionResponseAck_sequence_of[1] = {
  { &hf_h248_TransactionResponseAck_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_h248_TransactionAck },
};

static int
dissect_h248_TransactionResponseAck(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      TransactionResponseAck_sequence_of, hf_index, ett_h248_TransactionResponseAck);

  return offset;
}



static int
dissect_h248_T_seg_rep_transactionId(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    uint32_t trx_id = 0;
	offset = dissect_h248_trx_id(implicit_tag, actx->pinfo, tree, tvb, offset, &trx_id);
    curr_info.trx = gcp_trx(curr_info.msg, trx_id, GCP_TRX_ACK, actx->pinfo, keep_persistent_data);
    error_code = 0;


  return offset;
}


static const ber_sequence_t SegmentReply_sequence[] = {
  { &hf_h248_seg_rep_transactionId, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_T_seg_rep_transactionId },
  { &hf_h248_segmentNumber  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_h248_SegmentNumber },
  { &hf_h248_segmentationComplete, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_NULL },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_SegmentReply(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SegmentReply_sequence, hf_index, ett_h248_SegmentReply);

  return offset;
}


static const value_string h248_Transaction_vals[] = {
  {   0, "transactionRequest" },
  {   1, "transactionPending" },
  {   2, "transactionReply" },
  {   3, "transactionResponseAck" },
  {   4, "segmentReply" },
  { 0, NULL }
};

static const ber_choice_t Transaction_choice[] = {
  {   0, &hf_h248_transactionRequest, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_TransactionRequest },
  {   1, &hf_h248_transactionPending, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_h248_TransactionPending },
  {   2, &hf_h248_transactionReply, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_h248_TransactionReply },
  {   3, &hf_h248_transactionResponseAck, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_h248_TransactionResponseAck },
  {   4, &hf_h248_segmentReply   , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_h248_SegmentReply },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_Transaction(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Transaction_choice, hf_index, ett_h248_Transaction,
                                 NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_Transaction_sequence_of[1] = {
  { &hf_h248_transactions_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_h248_Transaction },
};

static int
dissect_h248_SEQUENCE_OF_Transaction(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_Transaction_sequence_of, hf_index, ett_h248_SEQUENCE_OF_Transaction);

  return offset;
}


static const value_string h248_T_messageBody_vals[] = {
  {   0, "messageError" },
  {   1, "transactions" },
  { 0, NULL }
};

static const ber_choice_t T_messageBody_choice[] = {
  {   0, &hf_h248_messageError   , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_ErrorDescriptor },
  {   1, &hf_h248_transactions   , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_h248_SEQUENCE_OF_Transaction },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_T_messageBody(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_messageBody_choice, hf_index, ett_h248_T_messageBody,
                                 NULL);

  return offset;
}


static const ber_sequence_t Message_sequence[] = {
  { &hf_h248_version        , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_T_version },
  { &hf_h248_mId            , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_h248_MId },
  { &hf_h248_messageBody    , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_h248_T_messageBody },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_Message(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    curr_info.msg = gcp_msg(actx->pinfo,tvb_raw_offset(tvb),keep_persistent_data);
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Message_sequence, hf_index, ett_h248_Message);

    col_add_str(actx->pinfo->cinfo, COL_INFO, gcp_msg_to_str(curr_info.msg,actx->pinfo->pool,keep_persistent_data));

    if (keep_persistent_data)
        gcp_analyze_msg(h248_tree, actx->pinfo, tvb, curr_info.msg, &h248_arrel, &ei_h248_errored_command);
  return offset;
}


static const ber_sequence_t MegacoMessage_sequence[] = {
  { &hf_h248_authHeader     , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h248_AuthenticationHeader },
  { &hf_h248_mess           , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_h248_Message },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_MegacoMessage(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MegacoMessage_sequence, hf_index, ett_h248_MegacoMessage);

  return offset;
}



static int
dissect_h248_ServiceChangeReasonStr(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const value_string h248_AuditResultV1_vals[] = {
  {   0, "contectAuditResult" },
  {   1, "terminationAuditResult" },
  { 0, NULL }
};

static const ber_choice_t AuditResultV1_choice[] = {
  {   0, &hf_h248_contectAuditResult, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_TerminationID },
  {   1, &hf_h248_terminationAuditResult, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_h248_TerminationAudit },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_AuditResultV1(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 AuditResultV1_choice, hf_index, ett_h248_AuditResultV1,
                                 NULL);

  return offset;
}


static const ber_sequence_t AuditReplyV1_sequence[] = {
  { &hf_h248_terminationID  , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_TerminationID },
  { &hf_h248_audit_result   , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_h248_AuditResultV1 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_AuditReplyV1(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
/* h248v1 support */
	offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
		AuditReplyV1_sequence, hf_h248_auditValueReplyV1, ett_h248_AuditReplyV1);

  return offset;
}



static const ber_sequence_t EventParameterV1_sequence[] = {
  { &hf_h248_eventParamterName, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_EventParameterName },
  { &hf_h248_event_param_value, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_h248_EventParamValueV1 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_EventParameterV1(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EventParameterV1_sequence, hf_index, ett_h248_EventParameterV1);

  return offset;
}



static const ber_sequence_t SigParameterV1_sequence[] = {
  { &hf_h248_sigParameterName, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_h248_SigParameterName },
  { &hf_h248_sig_param_value, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_h248_SigParamValueV1 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_h248_SigParameterV1(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SigParameterV1_sequence, hf_index, ett_h248_SigParameterV1);

  return offset;
}


static int dissect_h248_tpkt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_) {
    dissect_tpkt_encap(tvb, pinfo, tree, h248_desegment, h248_handle);
    return tvb_captured_length(tvb);
}

static int
dissect_h248(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_item *h248_item;
    asn1_ctx_t asn1_ctx;
    h248_tree = NULL;

    asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);

    curr_info.msg = NULL;
    curr_info.trx = NULL;
    curr_info.ctx = NULL;
    curr_info.cmd = NULL;
    curr_info.term = NULL;
    curr_info.pkg = NULL;
    curr_info.evt = NULL;
    curr_info.sig = NULL;
    curr_info.stat = NULL;
    curr_info.par = NULL;

    /* Check if it is actually a text-based H.248 encoding, which we
       dissect with the "megaco" dissector in Wireshark.  (Both
       encodings are MEGACO (RFC 3015) and both are H.248.)
     */
    if(tvb_captured_length(tvb)>=6){
        if(!tvb_strneql(tvb, 0, "MEGACO", 6)){
            static dissector_handle_t megaco_handle=NULL;
            if(!megaco_handle){
                megaco_handle = find_dissector("megaco");
            }
            if(megaco_handle){
                call_dissector(megaco_handle, tvb, pinfo, tree);
                return tvb_captured_length(tvb);
            }
        }
        {
            proto_item *hidden_item = NULL;
            uint32_t magic_num = 0, offset = 0;
            magic_num = tvb_get_ntohl(tvb, offset);
            hidden_item = proto_tree_add_uint(tree, hf_248_magic_num, tvb, offset, 4, magic_num);
            proto_item_set_hidden(hidden_item);
            if( dissector_try_uint(subdissector_table, magic_num, tvb, pinfo, tree) ) {
                return tvb_captured_length(tvb);
            }
        }
    }

    export_h248_pdu(pinfo, tvb);

    /* Make entry in the Protocol column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "H.248");

    if (tree) {
        h248_item = proto_tree_add_item(tree, proto_h248, tvb, 0, -1, ENC_NA);
        h248_tree = proto_item_add_subtree(h248_item, ett_h248);
    }

    dissect_h248_MegacoMessage(false, tvb, 0, &asn1_ctx, h248_tree, -1);

    return tvb_captured_length(tvb);
}

/*--- proto_register_h248 ----------------------------------------------*/
void proto_reg_handoff_h248(void);

void proto_register_h248(void) {

    /* List of fields */
    static hf_register_info hf[] = {
        { &hf_248_magic_num,
          { "Magic Number for Avaya H.248", "h248.magic_num",
            FT_UINT32, BASE_HEX, NULL, 0,
            NULL, HFILL}},
        { &hf_h248_mtpaddress_ni,
          { "NI", "h248.mtpaddress.ni",
            FT_UINT32, BASE_DEC, NULL, 0,
            NULL, HFILL }},
        { &hf_h248_mtpaddress_pc,
          { "PC", "h248.mtpaddress.pc",
            FT_UINT32, BASE_DEC, NULL, 0,
            NULL, HFILL }},
        { &hf_h248_pkg_name,
          { "Package", "h248.package_name",
            FT_UINT16, BASE_HEX, NULL, 0,
            NULL, HFILL }},
        { &hf_248_pkg_param,
          { "Parameter ID", "h248.package_paramid",
            FT_UINT16, BASE_HEX, NULL, 0,
            NULL, HFILL }},
        { &hf_h248_signal_code,
          { "Signal ID", "h248.package_signalid",
            FT_UINT16, BASE_HEX, NULL, 0,
            NULL, HFILL }},
        { &hf_h248_event_code,
          { "Event ID", "h248.package_eventid",
            FT_UINT16, BASE_HEX, NULL, 0,
            NULL, HFILL }},
        { &hf_h248_event_name,
          { "Package and Event name", "h248.event_name",
            FT_UINT32, BASE_HEX, NULL, 0,
            NULL, HFILL }},
        { &hf_h248_signal_name,
          { "Package and Signal name", "h248.signal_name",
            FT_UINT32, BASE_HEX, NULL, 0,
            NULL, HFILL }},
        { &hf_h248_pkg_bcp_BNCChar_PDU,
          { "BNCChar", "h248.package_bcp.BNCChar",
            FT_UINT32, BASE_DEC, VALS(gcp_term_types), 0,
            NULL, HFILL }},
        { &hf_h248_context_id,
          { "contextId", "h248.contextId",
            FT_UINT32, BASE_HEX, NULL, 0,
            "Context ID", HFILL }},
        { &hf_h248_term_wild_type,
          { "Wildcard Mode", "h248.term.wildcard.mode",
            FT_UINT8, BASE_DEC, VALS(wildcard_modes), 0x80,
            NULL, HFILL }},
        { &hf_h248_term_wild_level,
          { "Wildcarding Level", "h248.term.wildcard.level",
            FT_UINT8, BASE_DEC, VALS(wildcard_levels), 0x40,
            NULL, HFILL }},
        { &hf_h248_term_wild_position,
          { "Wildcarding Position", "h248.term.wildcard.pos",
            FT_UINT8, BASE_DEC, NULL, 0x3F,
            NULL, HFILL }},

        { &hf_h248_no_pkg,
          { "Unknown Package", "h248.pkg.unknown",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }},
        { &hf_h248_no_sig,
          { "Unknown Signal", "h248.pkg.unknown.sig",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }},
        { &hf_h248_no_evt,
          { "Unknown Event", "h248.pkg.unknown.evt",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }},
        { &hf_h248_param,
          { "Parameter", "h248.pkg.unknown.param",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }},
        { &hf_h248_serviceChangeReasonStr,
          { "ServiceChangeReasonStr", "h248.serviceChangeReasonstr",
            FT_STRING, BASE_NONE, NULL, 0,
            "h248.IA5String", HFILL }},
        { &hf_h248_context_id64,
          { "contextId", "h248.contextId64",
            FT_UINT64, BASE_HEX, NULL, 0,
            "Context ID", HFILL }},
        { &hf_h248_transactionId64,
          { "transactionId", "h248.transactionId",
            FT_UINT64, BASE_DEC, NULL, 0,
            NULL, HFILL }},

/* h248v1 support */
        { &hf_h248_auditValueReplyV1,
          { "auditValueReplyV1", "h248.auditValueReplyV1",
            FT_NONE, BASE_NONE, NULL, 0,
            NULL, HFILL }},

    { &hf_h248_authHeader,
      { "authHeader", "h248.authHeader_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AuthenticationHeader", HFILL }},
    { &hf_h248_mess,
      { "mess", "h248.mess_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Message", HFILL }},
    { &hf_h248_secParmIndex,
      { "secParmIndex", "h248.secParmIndex",
        FT_BYTES, BASE_NONE, NULL, 0,
        "SecurityParmIndex", HFILL }},
    { &hf_h248_seqNum,
      { "seqNum", "h248.seqNum",
        FT_BYTES, BASE_NONE, NULL, 0,
        "SequenceNum", HFILL }},
    { &hf_h248_ad,
      { "ad", "h248.ad",
        FT_BYTES, BASE_NONE, NULL, 0,
        "AuthData", HFILL }},
    { &hf_h248_version,
      { "version", "h248.version",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_mId,
      { "mId", "h248.mId",
        FT_UINT32, BASE_DEC, VALS(h248_MId_vals), 0,
        NULL, HFILL }},
    { &hf_h248_messageBody,
      { "messageBody", "h248.messageBody",
        FT_UINT32, BASE_DEC, VALS(h248_T_messageBody_vals), 0,
        NULL, HFILL }},
    { &hf_h248_messageError,
      { "messageError", "h248.messageError_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ErrorDescriptor", HFILL }},
    { &hf_h248_transactions,
      { "transactions", "h248.transactions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Transaction", HFILL }},
    { &hf_h248_transactions_item,
      { "Transaction", "h248.Transaction",
        FT_UINT32, BASE_DEC, VALS(h248_Transaction_vals), 0,
        NULL, HFILL }},
    { &hf_h248_ip4Address,
      { "ip4Address", "h248.ip4Address_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_ip6Address,
      { "ip6Address", "h248.ip6Address_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_domainName,
      { "domainName", "h248.domainName_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_deviceName,
      { "deviceName", "h248.deviceName",
        FT_STRING, BASE_NONE, NULL, 0,
        "PathName", HFILL }},
    { &hf_h248_mtpAddress,
      { "mtpAddress", "h248.mtpAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_domName,
      { "name", "h248.domainname",
        FT_STRING, BASE_NONE, NULL, 0,
        "IA5String", HFILL }},
    { &hf_h248_portNumber,
      { "portNumber", "h248.portNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_h248_iP4Address,
      { "address", "h248.iP4Address",
        FT_IPv4, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_4", HFILL }},
    { &hf_h248_iP6Address,
      { "address", "h248.iP6Address",
        FT_IPv6, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_16", HFILL }},
    { &hf_h248_transactionRequest,
      { "transactionRequest", "h248.transactionRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_transactionPending,
      { "transactionPending", "h248.transactionPending_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_transactionReply,
      { "transactionReply", "h248.transactionReply_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_transactionResponseAck,
      { "transactionResponseAck", "h248.transactionResponseAck",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_segmentReply,
      { "segmentReply", "h248.segmentReply_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_transactionId,
      { "transactionId", "h248.transactionRequest.transactionId",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_actions,
      { "actions", "h248.actions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_ActionRequest", HFILL }},
    { &hf_h248_actions_item,
      { "ActionRequest", "h248.ActionRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_tpend_transactionId,
      { "transactionId", "h248.transactionpending.transactionId",
        FT_UINT32, BASE_DEC, NULL, 0,
        "T_tpend_transactionId", HFILL }},
    { &hf_h248_trep_transactionId,
      { "transactionId", "h248.transactionreply.transactionId",
        FT_UINT32, BASE_DEC, NULL, 0,
        "T_trep_transactionId", HFILL }},
    { &hf_h248_immAckRequired,
      { "immAckRequired", "h248.immAckRequired_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_transactionResult,
      { "transactionResult", "h248.transactionResult",
        FT_UINT32, BASE_DEC, VALS(h248_T_transactionResult_vals), 0,
        NULL, HFILL }},
    { &hf_h248_transactionError,
      { "transactionError", "h248.transactionError_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ErrorDescriptor", HFILL }},
    { &hf_h248_actionReplies,
      { "actionReplies", "h248.actionReplies",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_ActionReply", HFILL }},
    { &hf_h248_actionReplies_item,
      { "ActionReply", "h248.ActionReply_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_segmentNumber,
      { "segmentNumber", "h248.segmentNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_segmentationComplete,
      { "segmentationComplete", "h248.segmentationComplete_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_seg_rep_transactionId,
      { "transactionId", "h248.segmentreply.transactionId",
        FT_UINT32, BASE_DEC, NULL, 0,
        "T_seg_rep_transactionId", HFILL }},
    { &hf_h248_TransactionResponseAck_item,
      { "TransactionAck", "h248.TransactionAck_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_firstAck,
      { "firstAck", "h248.firstAck",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TransactionId", HFILL }},
    { &hf_h248_lastAck,
      { "lastAck", "h248.lastAck",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TransactionId", HFILL }},
    { &hf_h248_errorCode,
      { "errorCode", "h248.errorCode",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &h248_reasons_ext, 0,
        NULL, HFILL }},
    { &hf_h248_errorText,
      { "errorText", "h248.errorText",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_contextId,
      { "contextId", "h248.contextId",
        FT_UINT32, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_contextRequest,
      { "contextRequest", "h248.contextRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_contextAttrAuditReq,
      { "contextAttrAuditReq", "h248.contextAttrAuditReq_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_commandRequests,
      { "commandRequests", "h248.commandRequests",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_CommandRequest", HFILL }},
    { &hf_h248_commandRequests_item,
      { "CommandRequest", "h248.CommandRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_errorDescriptor,
      { "errorDescriptor", "h248.errorDescriptor_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_contextReply,
      { "contextReply", "h248.contextReply_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ContextRequest", HFILL }},
    { &hf_h248_commandReply,
      { "commandReply", "h248.commandReply",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_CommandReply", HFILL }},
    { &hf_h248_commandReply_item,
      { "CommandReply", "h248.CommandReply",
        FT_UINT32, BASE_DEC, VALS(h248_CommandReply_vals), 0,
        NULL, HFILL }},
    { &hf_h248_priority,
      { "priority", "h248.priority",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_15", HFILL }},
    { &hf_h248_emergency,
      { "emergency", "h248.emergency",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h248_topologyReq,
      { "topologyReq", "h248.topologyReq",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_topologyReq_item,
      { "TopologyRequest", "h248.TopologyRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_iepscallind_BOOL,
      { "iepscallind", "h248.iepscallind",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "Iepscallind_BOOL", HFILL }},
    { &hf_h248_contextProp,
      { "contextProp", "h248.contextProp",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_PropertyParm", HFILL }},
    { &hf_h248_contextProp_item,
      { "PropertyParm", "h248.PropertyParm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_contextList,
      { "contextList", "h248.contextList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_ContextIDinList", HFILL }},
    { &hf_h248_contextList_item,
      { "ContextIDinList", "h248.ContextIDinList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_topology,
      { "topology", "h248.topology_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_cAAREmergency,
      { "emergency", "h248.emergency_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_cAARPriority,
      { "priority", "h248.priority_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_iepscallind,
      { "iepscallind", "h248.iepscallind_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_contextPropAud,
      { "contextPropAud", "h248.contextPropAud",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_IndAudPropertyParm", HFILL }},
    { &hf_h248_contextPropAud_item,
      { "IndAudPropertyParm", "h248.IndAudPropertyParm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_selectpriority,
      { "selectpriority", "h248.selectpriority",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_15", HFILL }},
    { &hf_h248_selectemergency,
      { "selectemergency", "h248.selectemergency",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h248_selectiepscallind,
      { "selectiepscallind", "h248.selectiepscallind",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h248_selectLogic,
      { "selectLogic", "h248.selectLogic",
        FT_UINT32, BASE_DEC, VALS(h248_SelectLogic_vals), 0,
        NULL, HFILL }},
    { &hf_h248_andAUDITSelect,
      { "andAUDITSelect", "h248.andAUDITSelect_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_orAUDITSelect,
      { "orAUDITSelect", "h248.orAUDITSelect_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_command,
      { "command", "h248.command",
        FT_UINT32, BASE_DEC, VALS(h248_Command_vals), 0,
        NULL, HFILL }},
    { &hf_h248_optional,
      { "optional", "h248.optional_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_wildcardReturn,
      { "wildcardReturn", "h248.wildcardReturn_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_addReq,
      { "addReq", "h248.addReq_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_moveReq,
      { "moveReq", "h248.moveReq_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_modReq,
      { "modReq", "h248.modReq_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_subtractReq,
      { "subtractReq", "h248.subtractReq_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_auditCapRequest,
      { "auditCapRequest", "h248.auditCapRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_auditValueRequest,
      { "auditValueRequest", "h248.auditValueRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_notifyReq,
      { "notifyReq", "h248.notifyReq_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_serviceChangeReq,
      { "serviceChangeReq", "h248.serviceChangeReq_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ServiceChangeRequest", HFILL }},
    { &hf_h248_addReply,
      { "addReply", "h248.addReply_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_moveReply,
      { "moveReply", "h248.moveReply_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_modReply,
      { "modReply", "h248.modReply_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_subtractReply,
      { "subtractReply", "h248.subtractReply_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_auditCapReply,
      { "auditCapReply", "h248.auditCapReply",
        FT_UINT32, BASE_DEC, VALS(h248_AuditReply_vals), 0,
        NULL, HFILL }},
    { &hf_h248_auditValueReply,
      { "auditValueReply", "h248.auditValueReply",
        FT_UINT32, BASE_DEC, VALS(h248_AuditReply_vals), 0,
        NULL, HFILL }},
    { &hf_h248_notifyReply,
      { "notifyReply", "h248.notifyReply_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_serviceChangeReply,
      { "serviceChangeReply", "h248.serviceChangeReply_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_terminationFrom,
      { "terminationFrom", "h248.terminationFrom_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TerminationID", HFILL }},
    { &hf_h248_terminationTo,
      { "terminationTo", "h248.terminationTo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TerminationID", HFILL }},
    { &hf_h248_topologyDirection,
      { "topologyDirection", "h248.topologyDirection",
        FT_UINT32, BASE_DEC, VALS(h248_T_topologyDirection_vals), 0,
        NULL, HFILL }},
    { &hf_h248_streamID,
      { "streamID", "h248.streamID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_topologyDirectionExtension,
      { "topologyDirectionExtension", "h248.topologyDirectionExtension",
        FT_UINT32, BASE_DEC, VALS(h248_T_topologyDirectionExtension_vals), 0,
        NULL, HFILL }},
    { &hf_h248_terminationIDList,
      { "terminationID", "h248.terminationID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TerminationIDList", HFILL }},
    { &hf_h248_descriptors,
      { "descriptors", "h248.descriptors",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_AmmDescriptor", HFILL }},
    { &hf_h248_descriptors_item,
      { "AmmDescriptor", "h248.AmmDescriptor",
        FT_UINT32, BASE_DEC, VALS(h248_AmmDescriptor_vals), 0,
        NULL, HFILL }},
    { &hf_h248_mediaDescriptor,
      { "mediaDescriptor", "h248.mediaDescriptor_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_modemDescriptor,
      { "modemDescriptor", "h248.modemDescriptor_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_muxDescriptor,
      { "muxDescriptor", "h248.muxDescriptor_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_eventsDescriptor,
      { "eventsDescriptor", "h248.eventsDescriptor_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_eventBufferDescriptor,
      { "eventBufferDescriptor", "h248.eventBufferDescriptor",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_signalsDescriptor,
      { "signalsDescriptor", "h248.signalsDescriptor",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_digitMapDescriptor,
      { "digitMapDescriptor", "h248.digitMapDescriptor_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_auditDescriptor,
      { "auditDescriptor", "h248.auditDescriptor_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_aDstatisticsDescriptor,
      { "statisticsDescriptor", "h248.statisticsDescriptor",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_terminationAudit,
      { "terminationAudit", "h248.terminationAudit",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_terminationID,
      { "terminationID", "h248.terminationID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_contextAuditResult,
      { "contextAuditResult", "h248.contextAuditResult",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TerminationIDList", HFILL }},
    { &hf_h248_error,
      { "error", "h248.error_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ErrorDescriptor", HFILL }},
    { &hf_h248_auditResult,
      { "auditResult", "h248.auditResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_auditResultTermList,
      { "auditResultTermList", "h248.auditResultTermList_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TermListAuditResult", HFILL }},
    { &hf_h248_terminationAuditResult,
      { "terminationAuditResult", "h248.terminationAuditResult",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TerminationAudit", HFILL }},
    { &hf_h248_TerminationAudit_item,
      { "AuditReturnParameter", "h248.AuditReturnParameter",
        FT_UINT32, BASE_DEC, VALS(h248_AuditReturnParameter_vals), 0,
        NULL, HFILL }},
    { &hf_h248_observedEventsDescriptor,
      { "observedEventsDescriptor", "h248.observedEventsDescriptor_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_aRPstatisticsDescriptor,
      { "statisticsDescriptor", "h248.statisticsDescriptor",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_packagesDescriptor,
      { "packagesDescriptor", "h248.packagesDescriptor",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_emptyDescriptors,
      { "emptyDescriptors", "h248.emptyDescriptors_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AuditDescriptor", HFILL }},
    { &hf_h248_auditToken,
      { "auditToken", "h248.auditToken",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_auditPropertyToken,
      { "auditPropertyToken", "h248.auditPropertyToken",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_IndAuditParameter", HFILL }},
    { &hf_h248_auditPropertyToken_item,
      { "IndAuditParameter", "h248.IndAuditParameter",
        FT_UINT32, BASE_DEC, VALS(h248_IndAuditParameter_vals), 0,
        NULL, HFILL }},
    { &hf_h248_indaudmediaDescriptor,
      { "indaudmediaDescriptor", "h248.indaudmediaDescriptor_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_indaudeventsDescriptor,
      { "indaudeventsDescriptor", "h248.indaudeventsDescriptor_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_indaudeventBufferDescriptor,
      { "indaudeventBufferDescriptor", "h248.indaudeventBufferDescriptor_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_indaudsignalsDescriptor,
      { "indaudsignalsDescriptor", "h248.indaudsignalsDescriptor",
        FT_UINT32, BASE_DEC, VALS(h248_IndAudSignalsDescriptor_vals), 0,
        NULL, HFILL }},
    { &hf_h248_indauddigitMapDescriptor,
      { "indauddigitMapDescriptor", "h248.indauddigitMapDescriptor_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_indaudstatisticsDescriptor,
      { "indaudstatisticsDescriptor", "h248.indaudstatisticsDescriptor_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_indaudpackagesDescriptor,
      { "indaudpackagesDescriptor", "h248.indaudpackagesDescriptor_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_indAudTerminationStateDescriptor,
      { "termStateDescr", "h248.termStateDescr_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "IndAudTerminationStateDescriptor", HFILL }},
    { &hf_h248_indAudMediaDescriptorStreams,
      { "streams", "h248.streams",
        FT_UINT32, BASE_DEC, VALS(h248_IndAudMediaDescriptorStreams_vals), 0,
        "IndAudMediaDescriptorStreams", HFILL }},
    { &hf_h248_oneStream,
      { "oneStream", "h248.oneStream_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "IndAudStreamParms", HFILL }},
    { &hf_h248_multiStream,
      { "multiStream", "h248.multiStream",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_IndAudStreamDescriptor", HFILL }},
    { &hf_h248_multiStream_item,
      { "IndAudStreamDescriptor", "h248.IndAudStreamDescriptor_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_indAudStreamParms,
      { "streamParms", "h248.streamParms_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "IndAudStreamParms", HFILL }},
    { &hf_h248_iASPLocalControlDescriptor,
      { "localControlDescriptor", "h248.localControlDescriptor_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "IndAudLocalControlDescriptor", HFILL }},
    { &hf_h248_iASPLocalDescriptor,
      { "localDescriptor", "h248.localDescriptor_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "IndAudLocalRemoteDescriptor", HFILL }},
    { &hf_h248_iASPRemoteDescriptor,
      { "remoteDescriptor", "h248.remoteDescriptor_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "IndAudLocalRemoteDescriptor", HFILL }},
    { &hf_h248_statisticsDescriptor,
      { "statisticsDescriptor", "h248.statisticsDescriptor_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "IndAudStatisticsDescriptor", HFILL }},
    { &hf_h248_iALCDStreamMode,
      { "streamMode", "h248.streamMode_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_iALCDReserveValue,
      { "reserveValue", "h248.reserveValue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_iALCDReserveGroup,
      { "reserveGroup", "h248.reserveGroup_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_indAudPropertyParms,
      { "propertyParms", "h248.propertyParms",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_IndAudPropertyParm", HFILL }},
    { &hf_h248_indAudPropertyParms_item,
      { "IndAudPropertyParm", "h248.IndAudPropertyParm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_streamModeSel,
      { "streamModeSel", "h248.streamModeSel",
        FT_UINT32, BASE_DEC, VALS(h248_StreamMode_vals), 0,
        "StreamMode", HFILL }},
    { &hf_h248_name,
      { "name", "h248.name",
        FT_BYTES, BASE_NONE, NULL, 0,
        "PkgdName", HFILL }},
    { &hf_h248_propertyParms,
      { "propertyParms", "h248.propertyParms_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PropertyParm", HFILL }},
    { &hf_h248_propGroupID,
      { "propGroupID", "h248.propGroupID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_h248_iAPropertyGroup,
      { "propGrps", "h248.propGrps",
        FT_UINT32, BASE_DEC, NULL, 0,
        "IndAudPropertyGroup", HFILL }},
    { &hf_h248_IndAudPropertyGroup_item,
      { "IndAudPropertyParm", "h248.IndAudPropertyParm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_eventBufferControl,
      { "eventBufferControl", "h248.eventBufferControl_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_iATSDServiceState,
      { "serviceState", "h248.serviceState_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_serviceStateSel,
      { "serviceStateSel", "h248.serviceStateSel",
        FT_UINT32, BASE_DEC, VALS(h248_ServiceState_vals), 0,
        "ServiceState", HFILL }},
    { &hf_h248_requestID,
      { "requestID", "h248.requestID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_iAEDPkgdName,
      { "pkgdName", "h248.pkgdName",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_iAEBDEventName,
      { "eventName", "h248.eventName",
        FT_BYTES, BASE_NONE, NULL, 0,
        "PkgdName", HFILL }},
    { &hf_h248_indAudSignal,
      { "signal", "h248.signal_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "IndAudSignal", HFILL }},
    { &hf_h248_indAudSeqSigList,
      { "seqSigList", "h248.seqSigList_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "IndAudSeqSigList", HFILL }},
    { &hf_h248_id,
      { "id", "h248.id",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_h248_iASignalList,
      { "signalList", "h248.signalList_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "IndAudSignal", HFILL }},
    { &hf_h248_iASignalName,
      { "signalName", "h248.signalName",
        FT_BYTES, BASE_NONE, NULL, 0,
        "PkgdName", HFILL }},
    { &hf_h248_signalRequestID,
      { "signalRequestID", "h248.signalRequestID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RequestID", HFILL }},
    { &hf_h248_digitMapName,
      { "digitMapName", "h248.digitMapName",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_iAStatName,
      { "statName", "h248.statName",
        FT_BYTES, BASE_NONE, NULL, 0,
        "PkgdName", HFILL }},
    { &hf_h248_packageName,
      { "packageName", "h248.packageName",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Name", HFILL }},
    { &hf_h248_packageVersion,
      { "packageVersion", "h248.packageVersion",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_99", HFILL }},
    { &hf_h248_requestId,
      { "requestId", "h248.requestId",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_observedEventLst,
      { "observedEventLst", "h248.observedEventLst",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_ObservedEvent", HFILL }},
    { &hf_h248_observedEventLst_item,
      { "ObservedEvent", "h248.ObservedEvent_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_eventName,
      { "eventName", "h248.eventName",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_eventParList,
      { "eventParList", "h248.eventParList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_EventParameter", HFILL }},
    { &hf_h248_eventParList_item,
      { "EventParameter", "h248.EventParameter_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_timeNotation,
      { "timeNotation", "h248.timeNotation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_eventParameterName,
      { "eventParameterName", "h248.eventParameterName",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_eventParamValue,
      { "eventParamValue", "h248.eventParamValue",
        FT_UINT32, BASE_DEC, NULL, 0,
        "EventParamValues", HFILL }},
    { &hf_h248_eventPar_extraInfo,
      { "extraInfo", "h248.extraInfo",
        FT_UINT32, BASE_DEC, VALS(h248_EventPar_extraInfo_vals), 0,
        "EventPar_extraInfo", HFILL }},
    { &hf_h248_relation,
      { "relation", "h248.relation",
        FT_UINT32, BASE_DEC, VALS(h248_Relation_vals), 0,
        NULL, HFILL }},
    { &hf_h248_range,
      { "range", "h248.range",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h248_sublist,
      { "sublist", "h248.sublist",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h248_EventParamValues_item,
      { "EventParamValue", "h248.EventParamValue",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_serviceChangeParms,
      { "serviceChangeParms", "h248.serviceChangeParms_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ServiceChangeParm", HFILL }},
    { &hf_h248_serviceChangeResult,
      { "serviceChangeResult", "h248.serviceChangeResult",
        FT_UINT32, BASE_DEC, VALS(h248_ServiceChangeResult_vals), 0,
        NULL, HFILL }},
    { &hf_h248_serviceChangeResParms,
      { "serviceChangeResParms", "h248.serviceChangeResParms_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ServiceChangeResParm", HFILL }},
    { &hf_h248_wildcard,
      { "wildcard", "h248.wildcard",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_WildcardField", HFILL }},
    { &hf_h248_wildcard_item,
      { "WildcardField", "h248.WildcardField",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_terminationId,
      { "id", "h248.terminationId",
        FT_BYTES, BASE_NONE, NULL, 0,
        "T_terminationId", HFILL }},
    { &hf_h248_TerminationIDList_item,
      { "TerminationID", "h248.TerminationID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_termStateDescr,
      { "termStateDescr", "h248.termStateDescr_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TerminationStateDescriptor", HFILL }},
    { &hf_h248_streams,
      { "streams", "h248.streams",
        FT_UINT32, BASE_DEC, VALS(h248_T_streams_vals), 0,
        NULL, HFILL }},
    { &hf_h248_mediaDescriptorOneStream,
      { "oneStream", "h248.oneStream_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "StreamParms", HFILL }},
    { &hf_h248_mediaDescriptorMultiStream,
      { "multiStream", "h248.multiStream",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_StreamDescriptor", HFILL }},
    { &hf_h248_mediaDescriptorMultiStream_item,
      { "StreamDescriptor", "h248.StreamDescriptor_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_streamParms,
      { "streamParms", "h248.streamParms_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_localControlDescriptor,
      { "localControlDescriptor", "h248.localControlDescriptor_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_localDescriptor,
      { "localDescriptor", "h248.localDescriptor_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "LocalRemoteDescriptor", HFILL }},
    { &hf_h248_remoteDescriptor,
      { "remoteDescriptor", "h248.remoteDescriptor_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "LocalRemoteDescriptor", HFILL }},
    { &hf_h248_sPstatisticsDescriptor,
      { "statisticsDescriptor", "h248.statisticsDescriptor",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_streamMode,
      { "streamMode", "h248.streamMode",
        FT_UINT32, BASE_DEC, VALS(h248_StreamMode_vals), 0,
        NULL, HFILL }},
    { &hf_h248_reserveValue,
      { "reserveValue", "h248.reserveValue",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h248_reserveGroup,
      { "reserveGroup", "h248.reserveGroup",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h248_lCDpropertyParms,
      { "propertyParms", "h248.propertyParms",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_PropertyParm", HFILL }},
    { &hf_h248_lCDpropertyParms_item,
      { "PropertyParm", "h248.PropertyParm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_propertyName,
      { "propertyName", "h248.propertyName",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_propertyParamValue,
      { "value", "h248.propertyParamValue",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_PropertyID", HFILL }},
    { &hf_h248_propertyParamValue_item,
      { "PropertyID", "h248.PropertyID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_propParm_extraInfo,
      { "extraInfo", "h248.extraInfo",
        FT_UINT32, BASE_DEC, VALS(h248_PropParm_extraInfo_vals), 0,
        "PropParm_extraInfo", HFILL }},
    { &hf_h248_propGrps,
      { "propGrps", "h248.propGrps",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_PropertyGroup", HFILL }},
    { &hf_h248_propGrps_item,
      { "PropertyGroup", "h248.PropertyGroup",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_PropertyGroup_item,
      { "PropertyParm", "h248.PropertyParm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_tSDpropertyParms,
      { "propertyParms", "h248.propertyParms",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_PropertyParm", HFILL }},
    { &hf_h248_tSDpropertyParms_item,
      { "PropertyParm", "h248.PropertyParm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_tSEventBufferControl,
      { "eventBufferControl", "h248.eventBufferControl",
        FT_UINT32, BASE_DEC, VALS(h248_EventBufferControl_vals), 0,
        NULL, HFILL }},
    { &hf_h248_serviceState,
      { "serviceState", "h248.serviceState",
        FT_UINT32, BASE_DEC, VALS(h248_ServiceState_vals), 0,
        NULL, HFILL }},
    { &hf_h248_muxType,
      { "muxType", "h248.muxType",
        FT_UINT32, BASE_DEC, VALS(h248_MuxType_vals), 0,
        NULL, HFILL }},
    { &hf_h248_termList,
      { "termList", "h248.termList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_TerminationID", HFILL }},
    { &hf_h248_termList_item,
      { "TerminationID", "h248.TerminationID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_nonStandardData,
      { "nonStandardData", "h248.nonStandardData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_eventList,
      { "eventList", "h248.eventList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_RequestedEvent", HFILL }},
    { &hf_h248_eventList_item,
      { "RequestedEvent", "h248.RequestedEvent_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_eventAction,
      { "eventAction", "h248.eventAction_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RequestedActions", HFILL }},
    { &hf_h248_evParList,
      { "evParList", "h248.evParList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_EventParameter", HFILL }},
    { &hf_h248_evParList_item,
      { "EventParameter", "h248.EventParameter_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_secondEvent,
      { "secondEvent", "h248.secondEvent_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SecondEventsDescriptor", HFILL }},
    { &hf_h248_notifyImmediate,
      { "notifyImmediate", "h248.notifyImmediate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_notifyRegulated,
      { "notifyRegulated", "h248.notifyRegulated_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RegulatedEmbeddedDescriptor", HFILL }},
    { &hf_h248_neverNotify,
      { "neverNotify", "h248.neverNotify_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_keepActive,
      { "keepActive", "h248.keepActive",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_h248_eventDM,
      { "eventDM", "h248.eventDM",
        FT_UINT32, BASE_DEC, VALS(h248_EventDM_vals), 0,
        NULL, HFILL }},
    { &hf_h248_notifyBehaviour,
      { "notifyBehaviour", "h248.notifyBehaviour",
        FT_UINT32, BASE_DEC, VALS(h248_NotifyBehaviour_vals), 0,
        NULL, HFILL }},
    { &hf_h248_resetEventsDescriptor,
      { "resetEventsDescriptor", "h248.resetEventsDescriptor_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_digitMapValue,
      { "digitMapValue", "h248.digitMapValue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_secondaryEventList,
      { "eventList", "h248.eventList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_SecondRequestedEvent", HFILL }},
    { &hf_h248_secondaryEventList_item,
      { "SecondRequestedEvent", "h248.SecondRequestedEvent_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_pkgdName,
      { "pkgdName", "h248.pkgdName",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_secondaryEventAction,
      { "eventAction", "h248.eventAction_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SecondRequestedActions", HFILL }},
    { &hf_h248_EventBufferDescriptor_item,
      { "EventSpec", "h248.EventSpec_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_SignalsDescriptor_item,
      { "SignalRequest", "h248.SignalRequest",
        FT_UINT32, BASE_DEC, VALS(h248_SignalRequest_vals), 0,
        NULL, HFILL }},
    { &hf_h248_signal,
      { "signal", "h248.signal_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_seqSigList,
      { "seqSigList", "h248.seqSigList_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_signalList,
      { "signalList", "h248.signalList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Signal", HFILL }},
    { &hf_h248_signalList_item,
      { "Signal", "h248.Signal_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_signalName,
      { "signalName", "h248.signalName",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_sigType,
      { "sigType", "h248.sigType",
        FT_UINT32, BASE_DEC, VALS(h248_SignalType_vals), 0,
        "SignalType", HFILL }},
    { &hf_h248_duration,
      { "duration", "h248.duration",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_h248_notifyCompletion,
      { "notifyCompletion", "h248.notifyCompletion",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_sigParList,
      { "sigParList", "h248.sigParList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_SigParameter", HFILL }},
    { &hf_h248_sigParList_item,
      { "SigParameter", "h248.SigParameter_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_direction,
      { "direction", "h248.direction",
        FT_UINT32, BASE_DEC, VALS(h248_SignalDirection_vals), 0,
        "SignalDirection", HFILL }},
    { &hf_h248_intersigDelay,
      { "intersigDelay", "h248.intersigDelay",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_h248_sigParameterName,
      { "sigParameterName", "h248.sigParameterName",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_value,
      { "value", "h248.value",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SigParamValues", HFILL }},
    { &hf_h248_extraInfo,
      { "extraInfo", "h248.extraInfo",
        FT_UINT32, BASE_DEC, VALS(h248_T_extraInfo_vals), 0,
        NULL, HFILL }},
    { &hf_h248_SigParamValues_item,
      { "SigParamValue", "h248.SigParamValue",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_mtl,
      { "mtl", "h248.mtl",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_ModemType", HFILL }},
    { &hf_h248_mtl_item,
      { "ModemType", "h248.ModemType",
        FT_UINT32, BASE_DEC, VALS(h248_ModemType_vals), 0,
        NULL, HFILL }},
    { &hf_h248_mpl,
      { "mpl", "h248.mpl",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_PropertyParm", HFILL }},
    { &hf_h248_mpl_item,
      { "PropertyParm", "h248.PropertyParm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_startTimer,
      { "startTimer", "h248.startTimer",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_99", HFILL }},
    { &hf_h248_shortTimer,
      { "shortTimer", "h248.shortTimer",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_99", HFILL }},
    { &hf_h248_longTimer,
      { "longTimer", "h248.longTimer",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_99", HFILL }},
    { &hf_h248_digitMapBody,
      { "digitMapBody", "h248.digitMapBody",
        FT_STRING, BASE_NONE, NULL, 0,
        "IA5String", HFILL }},
    { &hf_h248_durationTimer,
      { "durationTimer", "h248.durationTimer",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_99", HFILL }},
    { &hf_h248_serviceChangeMethod,
      { "serviceChangeMethod", "h248.serviceChangeMethod",
        FT_UINT32, BASE_DEC, VALS(h248_ServiceChangeMethod_vals), 0,
        NULL, HFILL }},
    { &hf_h248_serviceChangeAddress,
      { "serviceChangeAddress", "h248.serviceChangeAddress",
        FT_UINT32, BASE_DEC, VALS(h248_ServiceChangeAddress_vals), 0,
        NULL, HFILL }},
    { &hf_h248_serviceChangeVersion,
      { "serviceChangeVersion", "h248.serviceChangeVersion",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_99", HFILL }},
    { &hf_h248_serviceChangeProfile,
      { "serviceChangeProfile", "h248.serviceChangeProfile_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_serviceChangeReason,
      { "serviceChangeReason", "h248.serviceChangeReason",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SCreasonValue", HFILL }},
    { &hf_h248_serviceChangeDelay,
      { "serviceChangeDelay", "h248.serviceChangeDelay",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_4294967295", HFILL }},
    { &hf_h248_serviceChangeMgcId,
      { "serviceChangeMgcId", "h248.serviceChangeMgcId",
        FT_UINT32, BASE_DEC, VALS(h248_MId_vals), 0,
        "MId", HFILL }},
    { &hf_h248_timeStamp,
      { "timeStamp", "h248.timeStamp_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TimeNotation", HFILL }},
    { &hf_h248_serviceChangeInfo,
      { "serviceChangeInfo", "h248.serviceChangeInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AuditDescriptor", HFILL }},
    { &hf_h248_serviceChangeIncompleteFlag,
      { "serviceChangeIncompleteFlag", "h248.serviceChangeIncompleteFlag_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_SCreasonValue_item,
      { "SCreasonValueOctetStr", "h248.SCreasonValueOctetStr",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_timestamp,
      { "timestamp", "h248.timestamp_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TimeNotation", HFILL }},
    { &hf_h248_profileName,
      { "profileName", "h248.profileName",
        FT_STRING, BASE_NONE, NULL, 0,
        "IA5String_SIZE_1_67", HFILL }},
    { &hf_h248_PackagesDescriptor_item,
      { "PackagesItem", "h248.PackagesItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_StatisticsDescriptor_item,
      { "StatisticsParameter", "h248.StatisticsParameter_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_statName,
      { "statName", "h248.statName",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_statValue,
      { "statValue", "h248.statValue",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_nonStandardIdentifier,
      { "nonStandardIdentifier", "h248.nonStandardIdentifier",
        FT_UINT32, BASE_DEC, VALS(h248_NonStandardIdentifier_vals), 0,
        NULL, HFILL }},
    { &hf_h248_data,
      { "data", "h248.data",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_h248_object,
      { "object", "h248.object",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_h248_h221NonStandard,
      { "h221NonStandard", "h248.h221NonStandard_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_h248_experimental,
      { "experimental", "h248.experimental",
        FT_STRING, BASE_NONE, NULL, 0,
        "IA5String_SIZE_8", HFILL }},
    { &hf_h248_t35CountryCode1,
      { "t35CountryCode1", "h248.t35CountryCode1",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_h248_t35CountryCode2,
      { "t35CountryCode2", "h248.t35CountryCode2",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_h248_t35Extension,
      { "t35Extension", "h248.t35Extension",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_h248_manufacturerCode,
      { "manufacturerCode", "h248.manufacturerCode",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_h248_date,
      { "date", "h248.date",
        FT_STRING, BASE_NONE, NULL, 0,
        "IA5String_SIZE_8", HFILL }},
    { &hf_h248_time,
      { "time", "h248.time",
        FT_STRING, BASE_NONE, NULL, 0,
        "IA5String_SIZE_8", HFILL }},
    { &hf_h248_Value_item,
      { "Value item", "h248.Value_item",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_h248_audit_result,
      { "auditResult", "h248.auditResult",
        FT_UINT32, BASE_DEC, VALS(h248_AuditResultV1_vals), 0,
        "AuditResultV1", HFILL }},
    { &hf_h248_contectAuditResult,
      { "contectAuditResult", "h248.contectAuditResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TerminationID", HFILL }},
    { &hf_h248_eventParamterName,
      { "eventParamterName", "h248.eventParamterName",
        FT_BYTES, BASE_NONE, NULL, 0,
        "EventParameterName", HFILL }},
    { &hf_h248_event_param_value,
      { "value", "h248.event_param_value",
        FT_BYTES, BASE_NONE, NULL, 0,
        "EventParamValueV1", HFILL }},
    { &hf_h248_sig_param_value,
      { "value", "h248.sig_param_value",
        FT_BYTES, BASE_NONE, NULL, 0,
        "SigParamValueV1", HFILL }},
    { &hf_h248_T_auditToken_muxToken,
      { "muxToken", "h248.T.auditToken.muxToken",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_h248_T_auditToken_modemToken,
      { "modemToken", "h248.T.auditToken.modemToken",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_h248_T_auditToken_mediaToken,
      { "mediaToken", "h248.T.auditToken.mediaToken",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_h248_T_auditToken_eventsToken,
      { "eventsToken", "h248.T.auditToken.eventsToken",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_h248_T_auditToken_signalsToken,
      { "signalsToken", "h248.T.auditToken.signalsToken",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_h248_T_auditToken_digitMapToken,
      { "digitMapToken", "h248.T.auditToken.digitMapToken",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_h248_T_auditToken_statsToken,
      { "statsToken", "h248.T.auditToken.statsToken",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_h248_T_auditToken_observedEventsToken,
      { "observedEventsToken", "h248.T.auditToken.observedEventsToken",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_h248_T_auditToken_packagesToken,
      { "packagesToken", "h248.T.auditToken.packagesToken",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_h248_T_auditToken_eventBufferToken,
      { "eventBufferToken", "h248.T.auditToken.eventBufferToken",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_h248_NotifyCompletion_onTimeOut,
      { "onTimeOut", "h248.NotifyCompletion.onTimeOut",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_h248_NotifyCompletion_onInterruptByEvent,
      { "onInterruptByEvent", "h248.NotifyCompletion.onInterruptByEvent",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_h248_NotifyCompletion_onInterruptByNewSignalDescr,
      { "onInterruptByNewSignalDescr", "h248.NotifyCompletion.onInterruptByNewSignalDescr",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_h248_NotifyCompletion_otherReason,
      { "otherReason", "h248.NotifyCompletion.otherReason",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_h248_NotifyCompletion_onIteration,
      { "onIteration", "h248.NotifyCompletion.onIteration",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},

        GCP_HF_ARR_ELEMS("h248",h248_arrel)

    };

    /* List of subtrees */
    static int *ett[] = {
        &ett_h248,
        &ett_mtpaddress,
        &ett_packagename,
        &ett_codec,
        &ett_wildcard,
        &ett_h248_no_pkg,
        &ett_h248_no_sig,
        &ett_h248_no_evt,
        GCP_ETT_ARR_ELEMS(h248_arrel),

    &ett_h248_MegacoMessage,
    &ett_h248_AuthenticationHeader,
    &ett_h248_Message,
    &ett_h248_T_messageBody,
    &ett_h248_SEQUENCE_OF_Transaction,
    &ett_h248_MId,
    &ett_h248_DomainName,
    &ett_h248_IP4Address,
    &ett_h248_IP6Address,
    &ett_h248_Transaction,
    &ett_h248_TransactionRequest,
    &ett_h248_SEQUENCE_OF_ActionRequest,
    &ett_h248_TransactionPending,
    &ett_h248_TransactionReply,
    &ett_h248_T_transactionResult,
    &ett_h248_SEQUENCE_OF_ActionReply,
    &ett_h248_SegmentReply,
    &ett_h248_TransactionResponseAck,
    &ett_h248_TransactionAck,
    &ett_h248_ErrorDescriptor,
    &ett_h248_ActionRequest,
    &ett_h248_SEQUENCE_OF_CommandRequest,
    &ett_h248_ActionReply,
    &ett_h248_SEQUENCE_OF_CommandReply,
    &ett_h248_ContextRequest,
    &ett_h248_T_topologyReq,
    &ett_h248_SEQUENCE_OF_PropertyParm,
    &ett_h248_SEQUENCE_OF_ContextIDinList,
    &ett_h248_ContextAttrAuditRequest,
    &ett_h248_SEQUENCE_OF_IndAudPropertyParm,
    &ett_h248_SelectLogic,
    &ett_h248_CommandRequest,
    &ett_h248_Command,
    &ett_h248_CommandReply,
    &ett_h248_TopologyRequest,
    &ett_h248_AmmRequest,
    &ett_h248_SEQUENCE_OF_AmmDescriptor,
    &ett_h248_AmmDescriptor,
    &ett_h248_AmmsReply,
    &ett_h248_SubtractRequest,
    &ett_h248_AuditRequest,
    &ett_h248_AuditReply,
    &ett_h248_AuditResult,
    &ett_h248_TermListAuditResult,
    &ett_h248_TerminationAudit,
    &ett_h248_AuditReturnParameter,
    &ett_h248_AuditDescriptor,
    &ett_h248_T_auditToken,
    &ett_h248_SEQUENCE_OF_IndAuditParameter,
    &ett_h248_IndAuditParameter,
    &ett_h248_IndAudMediaDescriptor,
    &ett_h248_IndAudMediaDescriptorStreams,
    &ett_h248_SEQUENCE_OF_IndAudStreamDescriptor,
    &ett_h248_IndAudStreamDescriptor,
    &ett_h248_IndAudStreamParms,
    &ett_h248_IndAudLocalControlDescriptor,
    &ett_h248_IndAudPropertyParm,
    &ett_h248_IndAudLocalRemoteDescriptor,
    &ett_h248_IndAudPropertyGroup,
    &ett_h248_IndAudTerminationStateDescriptor,
    &ett_h248_IndAudEventsDescriptor,
    &ett_h248_IndAudEventBufferDescriptor,
    &ett_h248_IndAudSignalsDescriptor,
    &ett_h248_IndAudSeqSigList,
    &ett_h248_IndAudSignal,
    &ett_h248_IndAudDigitMapDescriptor,
    &ett_h248_IndAudStatisticsDescriptor,
    &ett_h248_IndAudPackagesDescriptor,
    &ett_h248_NotifyRequest,
    &ett_h248_NotifyReply,
    &ett_h248_ObservedEventsDescriptor,
    &ett_h248_SEQUENCE_OF_ObservedEvent,
    &ett_h248_ObservedEvent,
    &ett_h248_SEQUENCE_OF_EventParameter,
    &ett_h248_EventParameter,
    &ett_h248_EventPar_extraInfo,
    &ett_h248_EventParamValues,
    &ett_h248_ServiceChangeRequest,
    &ett_h248_ServiceChangeReply,
    &ett_h248_ServiceChangeResult,
    &ett_h248_TerminationID,
    &ett_h248_SEQUENCE_OF_WildcardField,
    &ett_h248_TerminationIDList,
    &ett_h248_MediaDescriptor,
    &ett_h248_T_streams,
    &ett_h248_SEQUENCE_OF_StreamDescriptor,
    &ett_h248_StreamDescriptor,
    &ett_h248_StreamParms,
    &ett_h248_LocalControlDescriptor,
    &ett_h248_PropertyParm,
    &ett_h248_SEQUENCE_OF_PropertyID,
    &ett_h248_PropParm_extraInfo,
    &ett_h248_LocalRemoteDescriptor,
    &ett_h248_SEQUENCE_OF_PropertyGroup,
    &ett_h248_PropertyGroup,
    &ett_h248_TerminationStateDescriptor,
    &ett_h248_MuxDescriptor,
    &ett_h248_SEQUENCE_OF_TerminationID,
    &ett_h248_EventsDescriptor,
    &ett_h248_SEQUENCE_OF_RequestedEvent,
    &ett_h248_RequestedEvent,
    &ett_h248_RegulatedEmbeddedDescriptor,
    &ett_h248_NotifyBehaviour,
    &ett_h248_RequestedActions,
    &ett_h248_EventDM,
    &ett_h248_SecondEventsDescriptor,
    &ett_h248_SEQUENCE_OF_SecondRequestedEvent,
    &ett_h248_SecondRequestedEvent,
    &ett_h248_SecondRequestedActions,
    &ett_h248_EventBufferDescriptor,
    &ett_h248_EventSpec,
    &ett_h248_SignalsDescriptor,
    &ett_h248_SignalRequest,
    &ett_h248_SeqSigList,
    &ett_h248_SEQUENCE_OF_Signal,
    &ett_h248_Signal,
    &ett_h248_SEQUENCE_OF_SigParameter,
    &ett_h248_NotifyCompletion,
    &ett_h248_SigParameter,
    &ett_h248_T_extraInfo,
    &ett_h248_SigParamValues,
    &ett_h248_ModemDescriptor,
    &ett_h248_SEQUENCE_OF_ModemType,
    &ett_h248_DigitMapDescriptor,
    &ett_h248_DigitMapValue,
    &ett_h248_ServiceChangeParm,
    &ett_h248_SCreasonValue,
    &ett_h248_ServiceChangeAddress,
    &ett_h248_ServiceChangeResParm,
    &ett_h248_ServiceChangeProfile,
    &ett_h248_PackagesDescriptor,
    &ett_h248_PackagesItem,
    &ett_h248_StatisticsDescriptor,
    &ett_h248_StatisticsParameter,
    &ett_h248_NonStandardData,
    &ett_h248_NonStandardIdentifier,
    &ett_h248_H221NonStandard,
    &ett_h248_TimeNotation,
    &ett_h248_Value,
    &ett_h248_AuditReplyV1,
    &ett_h248_AuditResultV1,
    &ett_h248_EventParameterV1,
    &ett_h248_SigParameterV1,
    };

    static ei_register_info ei[] = {
        { &ei_h248_errored_command, { "h248.errored_command", PI_RESPONSE_CODE, PI_WARN, "Errored Command", EXPFILL }},
        { &ei_h248_transactionId64, { "h248.transactionId.error", PI_MALFORMED, PI_WARN, "Transaction ID invalid", EXPFILL }},
        { &ei_h248_context_id64, { "h248.contextId.error", PI_MALFORMED, PI_WARN, "Context ID invalid", EXPFILL }},
        { &ei_h248_octet_string_expected, { "h248.octet_string_expected", PI_PROTOCOL, PI_WARN, "H.248 BER Error: OctetString expected", EXPFILL }},
    };

    expert_module_t* expert_h248;
    module_t *h248_module;

    /* Register protocol */
    proto_h248 = proto_register_protocol(PNAME, PSNAME, PFNAME);
    h248_handle = register_dissector("h248", dissect_h248, proto_h248);
    h248_tpkt_handle = register_dissector("h248.tpkt", dissect_h248_tpkt, proto_h248);

    /* Register fields and subtrees */
    proto_register_field_array(proto_h248, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_h248 = expert_register_protocol(proto_h248);
    expert_register_field_array(expert_h248, ei, array_length(ei));

    subdissector_table = register_dissector_table("h248.magic_num", "H.248 Magic Num", proto_h248, FT_UINT32, BASE_HEX);

    h248_module = prefs_register_protocol(proto_h248, NULL);
    prefs_register_bool_preference(h248_module, "ctx_info",
                                   "Track Context",
                                   "Maintain relationships between transactions and contexts and display an extra tree showing context data",
                                   &keep_persistent_data);
    prefs_register_bool_preference(h248_module, "desegment",
                                   "Desegment H.248 over TCP",
                                   "Desegment H.248 messages that span more TCP segments",
                                   &h248_desegment);

    gcp_msgs        = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
    gcp_trxs        = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
    gcp_ctxs_by_trx = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
    gcp_ctxs        = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());

    h248_tap = register_tap("h248");
}

/*--- proto_reg_handoff_h248 -------------------------------------------*/
void proto_reg_handoff_h248(void) {

    dissector_add_uint("mtp3.service_indicator", MTP_SI_GCP, h248_handle);
    h248_term_handle = find_dissector_add_dependency("h248term", proto_h248);
    dissector_add_uint_with_preference("tcp.port", H248_PORT, h248_tpkt_handle);
    dissector_add_uint_with_preference("udp.port", H248_PORT, h248_handle);

    ss7pc_address_type = address_type_get_by_name("AT_SS7PC");
    exported_pdu_tap = find_tap_id(EXPORT_PDU_TAP_NAME_LAYER_7);
}

