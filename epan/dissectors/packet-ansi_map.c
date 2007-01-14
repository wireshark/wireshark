/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* .\packet-ansi_map.c                                                        */
/* ../../tools/asn2wrs.py -b -e -p ansi_map -c ansi_map.cnf -s packet-ansi_map-template ansi_map.asn */

/* Input file: packet-ansi_map-template.c */

#line 1 "packet-ansi_map-template.c"
/* packet-ansi_map.c
 * Routines for ANSI 41 Mobile Application Part (IS41 MAP) dissection
 * Specications from 3GPP2 (www.3gpp2.org)
 * Based on the dissector by :
 * Michael Lum <mlum [AT] telostech.com>
 * In association with Telos Technology Inc.
 *
 * Copyright 2005 - 2007, Anders Broman <anders.broman@ericsson.com>
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
 * Credit to Tomas Kukosa for developing the asn2wrs compiler.
 *
 * Title		3GPP2			Other
 *
 *   Cellular Radiotelecommunications Intersystem Operations
 *			3GPP2 N.S0005-0 v 1.0		ANSI/TIA/EIA-41-D 
 *
 *   Network Support for MDN-Based Message Centers
 *			3GPP2 N.S0024-0 v1.0	IS-841
 *
 *   Enhanced International Calling
 *			3GPP2 N.S0027		IS-875
 *
 *   ANSI-41-D Miscellaneous Enhancements Revision 0
 *			3GPP2 N.S0015		PN-3590 (ANSI-41-E)
 *
 *   Authentication Enhancements
 *			3GPP2 N.S0014-0 v1.0	IS-778
 *
 *   Features In CDMA
 *			3GPP2 N.S0010-0 v1.0	IS-735
 *
 *   OTASP and OTAPA
 *			3GPP2 N.S0011-0 v1.0	IS-725-A
 *
 *   Circuit Mode Services
 *			3GPP2 N.S0008-0 v1.0	IS-737
 *	XXX SecondInterMSCCircuitID not implemented, parameter ID conflicts with ISLP Information!
 *
 *   IMSI
 *			3GPP2 N.S0009-0 v1.0	IS-751
 *
 *   WIN Phase 1
 *			3GPP2 N.S0013-0 v1.0	IS-771
 *
 *	 DCCH (Clarification of Audit Order with Forced 
 *         Re-Registration in pre-TIA/EIA-136-A Implementation 
 *			3GPP2 A.S0017-B			IS-730
 *
 *   UIM
 *			3GPP2 N.S0003
 *
 *   WIN Phase 2
 *			3GPP2 N.S0004-0 v1.0	IS-848
 *
 *   TIA/EIA-41-D Pre-Paid Charging
 *			3GPP2 N.S0018-0 v1.0	IS-826
 *
 *   User Selective Call Forwarding
 *			3GPP2 N.S0021-0 v1.0	IS-838
 *
 *
 *   Answer Hold
 *			3GPP2 N.S0022-0 v1.0	IS-837
 *
 *   UIM
 *			3GPP2 N.S0003
 *
 */ 

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/conversation.h>
#include <epan/tap.h>
#include <epan/emem.h>

#include <stdio.h>
#include <string.h>

#include "packet-ansi_map.h"
#include "packet-ansi_a.h"
#include "packet-gsm_map.h"
#include "packet-ber.h"
#include "packet-tcap.h"

#define PNAME  "ANSI Mobile Application Part"
#define PSNAME "ANSI MAP"
#define PFNAME "ansi_map"

/* Preferenc settings default */
#define MAX_SSN 254
static range_t *global_ssn_range;
static range_t *ssn_range;

static dissector_handle_t ansi_map_handle=NULL;

/* Initialize the protocol and registered fields */
static int ansi_map_tap = -1;
static int proto_ansi_map = -1;

static int hf_ansi_map_op_code_fam = -1;
static int hf_ansi_map_op_code = -1;

static int hf_ansi_map_reservedBitH = -1;
static int hf_ansi_map_reservedBitD = -1;
static int hf_ansi_map_reservedBitHG = -1;
static int hf_ansi_map_reservedBitED = -1;

static int hf_ansi_map_type_of_digits = -1;
static int hf_ansi_map_na = -1;
static int hf_ansi_map_pi = -1;
static int hf_ansi_map_navail = -1;
static int hf_ansi_map_si = -1;
static int hf_ansi_map_digits_enc = -1;
static int hf_ansi_map_np = -1;
static int hf_ansi_map_nr_digits = -1;
static int hf_ansi_map_bcd_digits = -1;
static int hf_ansi_map_ia5_digits = -1;
static int hf_ansi_map_subaddr_type = -1;
static int hf_ansi_map_subaddr_odd_even = -1;
static int hf_ansi_alertcode_cadence = -1;
static int hf_ansi_alertcode_pitch = -1;
static int hf_ansi_alertcode_alertaction = -1;
static int hf_ansi_map_announcementcode_tone = -1;
static int hf_ansi_map_announcementcode_class = -1;
static int hf_ansi_map_announcementcode_std_ann = -1;
static int hf_ansi_map_announcementcode_cust_ann = -1;
static int hf_ansi_map_authorizationperiod_period = -1;
static int hf_ansi_map_value = -1;
static int hf_ansi_map_msc_type = -1;
static int hf_ansi_map_handoffstate_pi = -1;
static int hf_ansi_map_tgn = -1;
static int hf_ansi_map_tmn = -1;
static int hf_ansi_map_messagewaitingnotificationcount_tom = -1;
static int hf_ansi_map_messagewaitingnotificationcount_no_mw = -1;
static int hf_ansi_map_messagewaitingnotificationtype_mwi = -1;
static int hf_ansi_map_messagewaitingnotificationtype_apt = -1;
static int hf_ansi_map_messagewaitingnotificationtype_pt = -1;

static int hf_ansi_map_trans_cap_prof = -1;
static int hf_ansi_map_trans_cap_busy = -1;
static int hf_ansi_map_trans_cap_ann = -1;
static int hf_ansi_map_trans_cap_rui = -1;
static int hf_ansi_map_trans_cap_spini = -1;
static int hf_ansi_map_trans_cap_uzci = -1;
static int hf_ansi_map_trans_cap_ndss = -1;
static int hf_ansi_map_trans_cap_nami = -1;
static int hf_ansi_trans_cap_multerm = -1;
static int hf_ansi_map_terminationtriggers_busy = -1;
static int hf_ansi_map_terminationtriggers_rf = -1;
static int hf_ansi_map_terminationtriggers_npr = -1;
static int hf_ansi_map_terminationtriggers_na = -1;
static int hf_ansi_map_terminationtriggers_nr = -1;
static int hf_ansi_trans_cap_tl = -1;
static int hf_ansi_map_cdmaserviceoption = -1;
static int hf_ansi_trans_cap_waddr = -1;
static int hf_ansi_map_MarketID = -1;
static int hf_ansi_map_swno = -1;
static int hf_ansi_map_idno = -1;
static int hf_ansi_map_segcount = -1;
static int hf_ansi_map_systemcapabilities_auth = -1;
static int hf_ansi_map_systemcapabilities_se = -1;
static int hf_ansi_map_systemcapabilities_vp = -1;
static int hf_ansi_map_systemcapabilities_cave = -1;
static int hf_ansi_map_systemcapabilities_ssd = -1;
static int hf_ansi_map_systemcapabilities_dp = -1;

static int hf_ansi_map_mslocation_lat = -1;
static int hf_ansi_map_mslocation_long = -1;
static int hf_ansi_map_mslocation_res = -1;
static int hf_ansi_map_nampscallmode_namps = -1;
static int hf_ansi_map_nampscallmode_amps = -1;
static int hf_ansi_map_nampschanneldata_navca = -1;
static int hf_ansi_map_nampschanneldata_CCIndicator = -1;

static int hf_ansi_map_callingfeaturesindicator_cfufa = -1;
static int hf_ansi_map_callingfeaturesindicator_cfbfa = -1;
static int hf_ansi_map_callingfeaturesindicator_cfnafa = -1;
static int hf_ansi_map_callingfeaturesindicator_cwfa = -1;
static int hf_ansi_map_callingfeaturesindicator_3wcfa = -1;
static int hf_ansi_map_callingfeaturesindicator_pcwfa =-1;
static int hf_ansi_map_callingfeaturesindicator_dpfa = -1;
static int hf_ansi_map_callingfeaturesindicator_ahfa = -1;
static int hf_ansi_map_callingfeaturesindicator_uscfvmfa = -1;
static int hf_ansi_map_callingfeaturesindicator_uscfmsfa = -1;
static int hf_ansi_map_callingfeaturesindicator_uscfnrfa = -1;
static int hf_ansi_map_callingfeaturesindicator_cpdsfa = -1;
static int hf_ansi_map_callingfeaturesindicator_ccsfa = -1;
static int hf_ansi_map_callingfeaturesindicator_epefa = -1;
static int hf_ansi_map_callingfeaturesindicator_cdfa = -1;
static int hf_ansi_map_callingfeaturesindicator_vpfa = -1;
static int hf_ansi_map_callingfeaturesindicator_ctfa = -1;
static int hf_ansi_map_callingfeaturesindicator_cnip1fa = -1;
static int hf_ansi_map_callingfeaturesindicator_cnip2fa = -1;
static int hf_ansi_map_callingfeaturesindicator_cnirfa = -1;
static int hf_ansi_map_callingfeaturesindicator_cniroverfa = -1;
static int hf_ansi_map_cdmacallmode_cdma = -1;
static int hf_ansi_map_cdmacallmode_amps = -1;
static int hf_ansi_map_cdmacallmode_namps = -1;
static int hf_ansi_map_cdmacallmode_cls1 = -1;
static int hf_ansi_map_cdmacallmode_cls2 = -1;
static int hf_ansi_map_cdmacallmode_cls3 = -1;
static int hf_ansi_map_cdmacallmode_cls4 = -1;
static int hf_ansi_map_cdmacallmode_cls5 = -1;
static int hf_ansi_map_cdmacallmode_cls6 = -1;
static int hf_ansi_map_cdmacallmode_cls7 = -1;
static int hf_ansi_map_cdmacallmode_cls8 = -1;
static int hf_ansi_map_cdmacallmode_cls9 = -1;
static int hf_ansi_map_cdmacallmode_cls10 = -1;
static int hf_ansi_map_cdmachanneldata_Frame_Offset = -1;
static int hf_ansi_map_cdmachanneldata_CDMA_ch_no = -1;
static int hf_ansi_map_cdmachanneldata_band_cls = -1;
static int hf_ansi_map_cdmachanneldata_lc_mask_b6 = -1;
static int hf_ansi_map_cdmachanneldata_lc_mask_b5 = -1;
static int hf_ansi_map_cdmachanneldata_lc_mask_b4 = -1;
static int hf_ansi_map_cdmachanneldata_lc_mask_b3 = -1;
static int hf_ansi_map_cdmachanneldata_lc_mask_b2 = -1;
static int hf_ansi_map_cdmachanneldata_lc_mask_b1 = -1;
static int hf_ansi_map_cdmachanneldata_np_ext = -1;
static int hf_ansi_map_cdmachanneldata_nominal_pwr = -1;
static int hf_ansi_map_cdmachanneldata_nr_preamble = -1;
 
static int hf_ansi_map_cdmastationclassmark_pc = -1;
static int hf_ansi_map_cdmastationclassmark_dtx = -1;
static int hf_ansi_map_cdmastationclassmark_smi = -1;
static int hf_ansi_map_cdmastationclassmark_dmi = -1;
static int hf_ansi_map_channeldata_vmac = -1;
static int hf_ansi_map_channeldata_dtx = -1;
static int hf_ansi_map_channeldata_scc = -1;
static int hf_ansi_map_channeldata_chno = -1;
static int hf_ansi_map_ConfidentialityModes_vp = -1;
static int hf_ansi_map_ConfidentialityModes_se = -1;
static int hf_ansi_map_deniedauthorizationperiod_period = -1;
static int hf_ansi_map_ConfidentialityModes_dp = -1;

static int hf_ansi_map_originationtriggers_all = -1;
static int hf_ansi_map_originationtriggers_local = -1;
static int hf_ansi_map_originationtriggers_ilata = -1;
static int hf_ansi_map_originationtriggers_olata = -1;
static int hf_ansi_map_originationtriggers_int = -1;
static int hf_ansi_map_originationtriggers_wz = -1;
static int hf_ansi_map_originationtriggers_unrec = -1;
static int hf_ansi_map_originationtriggers_rvtc = -1;
static int hf_ansi_map_originationtriggers_star = -1;
static int hf_ansi_map_originationtriggers_ds = -1;
static int hf_ansi_map_originationtriggers_pound = -1;
static int hf_ansi_map_originationtriggers_dp = -1;
static int hf_ansi_map_originationtriggers_pa = -1;
static int hf_ansi_map_originationtriggers_nodig = -1;
static int hf_ansi_map_originationtriggers_onedig = -1;
static int hf_ansi_map_originationtriggers_twodig = -1;
static int hf_ansi_map_originationtriggers_threedig = -1;
static int hf_ansi_map_originationtriggers_fourdig = -1;
static int hf_ansi_map_originationtriggers_fivedig = -1;
static int hf_ansi_map_originationtriggers_sixdig = -1;
static int hf_ansi_map_originationtriggers_sevendig = -1;
static int hf_ansi_map_originationtriggers_eightdig = -1;
static int hf_ansi_map_originationtriggers_ninedig = -1;
static int hf_ansi_map_originationtriggers_tendig = -1;
static int hf_ansi_map_originationtriggers_elevendig = -1;
static int hf_ansi_map_originationtriggers_thwelvedig = -1;
static int hf_ansi_map_originationtriggers_thirteendig = -1;
static int hf_ansi_map_originationtriggers_fourteendig = -1;
static int hf_ansi_map_originationtriggers_fifteendig = -1;
static int hf_ansi_map_triggercapability_init = -1;
static int hf_ansi_map_triggercapability_kdigit = -1;
static int hf_ansi_map_triggercapability_all = -1;
static int hf_ansi_map_triggercapability_rvtc = -1;
static int hf_ansi_map_triggercapability_oaa = -1;
static int hf_ansi_map_triggercapability_oans = -1;
static int hf_ansi_map_triggercapability_odisc = -1;
static int hf_ansi_map_triggercapability_ona = -1;
static int hf_ansi_map_triggercapability_ct = -1;
static int hf_ansi_map_triggercapability_unrec =-1;
static int hf_ansi_map_triggercapability_pa = -1;
static int hf_ansi_map_triggercapability_at = -1;
static int hf_ansi_map_triggercapability_cgraa = -1;
static int hf_ansi_map_triggercapability_it = -1;
static int hf_ansi_map_triggercapability_cdraa = -1;
static int hf_ansi_map_triggercapability_obsy = -1;
static int hf_ansi_map_triggercapability_tra = -1;
static int hf_ansi_map_triggercapability_tbusy = -1;
static int hf_ansi_map_triggercapability_tna = -1;
static int hf_ansi_map_triggercapability_tans = -1;
static int hf_ansi_map_triggercapability_tdisc = -1;
static int hf_ansi_map_winoperationscapability_conn = -1;
static int hf_ansi_map_winoperationscapability_ccdir = -1;
static int hf_ansi_map_winoperationscapability_pos = -1;
static int hf_ansi_map_PACA_Level = -1;
static int hf_ansi_map_pacaindicator_pa = -1;


/*--- Included file: packet-ansi_map-hf.c ---*/
#line 1 "packet-ansi_map-hf.c"
static int hf_ansi_map_AuthenticationDirective_PDU = -1;  /* AuthenticationDirective */
static int hf_ansi_map_AuthenticationDirectiveRes_PDU = -1;  /* AuthenticationDirectiveRes */
static int hf_ansi_map_OriginationRequest_PDU = -1;  /* OriginationRequest */
static int hf_ansi_map_OriginationRequestRes_PDU = -1;  /* OriginationRequestRes */
static int hf_ansi_map_invokeLast = -1;           /* InvokePDU */
static int hf_ansi_map_returnResultLast = -1;     /* ReturnResultPDU */
static int hf_ansi_map_returnError = -1;          /* ReturnErrorPDU */
static int hf_ansi_map_reject = -1;               /* RejectPDU */
static int hf_ansi_map_invokeNotLast = -1;        /* InvokePDU */
static int hf_ansi_map_returnResultNotLast = -1;  /* ReturnResultPDU */
static int hf_ansi_map_componentIDs = -1;         /* OCTET_STRING_SIZE_0_2 */
static int hf_ansi_map_operationCode = -1;        /* OperationCode */
static int hf_ansi_map_invokeParameters = -1;     /* InvokeParameters */
static int hf_ansi_map_componentID = -1;          /* ComponentID */
static int hf_ansi_map_returnResult = -1;         /* ReturnParameters */
static int hf_ansi_map_errorCode = -1;            /* ErrorCode */
static int hf_ansi_map_parameterre = -1;          /* RejectParameters */
static int hf_ansi_map_rejectProblem = -1;        /* ProblemPDU */
static int hf_ansi_map_parameterrj = -1;          /* RejectParameters */
static int hf_ansi_map_national = -1;             /* INTEGER_M32768_32767 */
static int hf_ansi_map_private = -1;              /* PrivateOperationCode */
static int hf_ansi_map_nationaler = -1;           /* INTEGER_M32768_32767 */
static int hf_ansi_map_privateer = -1;            /* INTEGER */
static int hf_ansi_map_electronicSerialNumber = -1;  /* ElectronicSerialNumber */
static int hf_ansi_map_msid = -1;                 /* MSID */
static int hf_ansi_map_authenticationAlgorithmVersion = -1;  /* AuthenticationAlgorithmVersion */
static int hf_ansi_map_authenticationResponseReauthentication = -1;  /* AuthenticationResponseReauthentication */
static int hf_ansi_map_authenticationResponseUniqueChallenge = -1;  /* AuthenticationResponseUniqueChallenge */
static int hf_ansi_map_callHistoryCount = -1;     /* CallHistoryCount */
static int hf_ansi_map_cdmaPrivateLongCodeMask = -1;  /* CDMAPrivateLongCodeMask */
static int hf_ansi_map_carrierDigits = -1;        /* CarrierDigits */
static int hf_ansi_map_denyAccess = -1;           /* DenyAccess */
static int hf_ansi_map_destinationDigits = -1;    /* DestinationDigits */
static int hf_ansi_map_locationAreaID = -1;       /* LocationAreaID */
static int hf_ansi_map_randomVariableReauthentication = -1;  /* RandomVariableReauthentication */
static int hf_ansi_map_mobileStationMIN = -1;     /* MobileStationMIN */
static int hf_ansi_map_mscid = -1;                /* MSCID */
static int hf_ansi_map_randomVariableSSD = -1;    /* RandomVariableSSD */
static int hf_ansi_map_randomVariableUniqueChallenge = -1;  /* RandomVariableUniqueChallenge */
static int hf_ansi_map_routingDigits = -1;        /* RoutingDigits */
static int hf_ansi_map_senderIdentificationNumber = -1;  /* SenderIdentificationNumber */
static int hf_ansi_map_sharedSecretData = -1;     /* SharedSecretData */
static int hf_ansi_map_signalingMessageEncryptionKey = -1;  /* SignalingMessageEncryptionKey */
static int hf_ansi_map_ssdnotShared = -1;         /* SSDNotShared */
static int hf_ansi_map_updateCount = -1;          /* UpdateCount */
static int hf_ansi_map_interMSCCircuitID = -1;    /* InterMSCCircuitID */
static int hf_ansi_map_mobileIdentificationNumber = -1;  /* MobileIdentificationNumber */
static int hf_ansi_map_countUpdateReport = -1;    /* CountUpdateReport */
static int hf_ansi_map_uniqueChallengeReport = -1;  /* UniqueChallengeReport */
static int hf_ansi_map_reportType = -1;           /* ReportType */
static int hf_ansi_map_systemAccessType = -1;     /* SystemAccessType */
static int hf_ansi_map_systemCapabilities = -1;   /* SystemCapabilities */
static int hf_ansi_map_callHistoryCountExpected = -1;  /* CallHistoryCountExpected */
static int hf_ansi_map_reportType2 = -1;          /* ReportType */
static int hf_ansi_map_terminalType = -1;         /* TerminalType */
static int hf_ansi_map_authenticationData = -1;   /* AuthenticationData */
static int hf_ansi_map_authenticationResponse = -1;  /* AuthenticationResponse */
static int hf_ansi_map_cdmaNetworkIdentification = -1;  /* CDMANetworkIdentification */
static int hf_ansi_map_confidentialityModes = -1;  /* ConfidentialityModes */
static int hf_ansi_map_controlChannelMode = -1;   /* ControlChannelMode */
static int hf_ansi_map_digits = -1;               /* Digits */
static int hf_ansi_map_pc_ssn = -1;               /* PC_SSN */
static int hf_ansi_map_randomVariable = -1;       /* RandomVariable */
static int hf_ansi_map_serviceRedirectionCause = -1;  /* ServiceRedirectionCause */
static int hf_ansi_map_suspiciousAccess = -1;     /* SuspiciousAccess */
static int hf_ansi_map_transactionCapability = -1;  /* TransactionCapability */
static int hf_ansi_map_analogRedirectRecord = -1;  /* AnalogRedirectRecord */
static int hf_ansi_map_cdmaRedirectRecord = -1;   /* CDMARedirectRecord */
static int hf_ansi_map_dataKey = -1;              /* DataKey */
static int hf_ansi_map_roamingIndication = -1;    /* RoamingIndication */
static int hf_ansi_map_serviceRedirectionInfo = -1;  /* ServiceRedirectionInfo */
static int hf_ansi_map_voicePrivacyMask = -1;     /* VoicePrivacyMask */
static int hf_ansi_map_reauthenticationReport = -1;  /* ReauthenticationReport */
static int hf_ansi_map_serviceIndicator = -1;     /* ServiceIndicator */
static int hf_ansi_map_signalingMessageEncryptionReport = -1;  /* SignalingMessageEncryptionReport */
static int hf_ansi_map_ssdUpdateReport = -1;      /* SSDUpdateReport */
static int hf_ansi_map_voicePrivacyReport = -1;   /* VoicePrivacyReport */
static int hf_ansi_map_randomVariableBaseStation = -1;  /* RandomVariableBaseStation */
static int hf_ansi_map_authenticationResponseBaseStation = -1;  /* AuthenticationResponseBaseStation */
static int hf_ansi_map_billingID = -1;            /* BillingID */
static int hf_ansi_map_channelData = -1;          /* ChannelData */
static int hf_ansi_map_interSwitchCount = -1;     /* InterSwitchCount */
static int hf_ansi_map_servingCellID = -1;        /* ServingCellID */
static int hf_ansi_map_stationClassMark = -1;     /* StationClassMark */
static int hf_ansi_map_targetCellID = -1;         /* TargetCellID */
static int hf_ansi_map_handoffReason = -1;        /* HandoffReason */
static int hf_ansi_map_handoffState = -1;         /* HandoffState */
static int hf_ansi_map_tdmaBurstIndicator = -1;   /* TDMABurstIndicator */
static int hf_ansi_map_tdmaCallMode = -1;         /* TDMACallMode */
static int hf_ansi_map_tdmaChannelData = -1;      /* TDMAChannelData */
static int hf_ansi_map_baseStationManufacturerCode = -1;  /* BaseStationManufacturerCode */
static int hf_ansi_map_alertCode = -1;            /* AlertCode */
static int hf_ansi_map_cdma2000HandoffInvokeIOSData = -1;  /* CDMA2000HandoffInvokeIOSData */
static int hf_ansi_map_cdmaCallMode = -1;         /* CDMACallMode */
static int hf_ansi_map_cdmaChannelData = -1;      /* CDMAChannelData */
static int hf_ansi_map_cdmaConnectionReferenceList = -1;  /* CDMAConnectionReferenceList */
static int hf_ansi_map_cdmaMobileProtocolRevision = -1;  /* CDMAMobileProtocolRevision */
static int hf_ansi_map_cdmaMSMeasuredChannelIdentity = -1;  /* CDMAMSMeasuredChannelIdentity */
static int hf_ansi_map_cdmaServiceConfigurationRecord = -1;  /* CDMAServiceConfigurationRecord */
static int hf_ansi_map_cdmaServiceOptionList = -1;  /* CDMAServiceOptionList */
static int hf_ansi_map_cdmaServingOneWayDelay = -1;  /* CDMAServingOneWayDelay */
static int hf_ansi_map_cdmaStationClassMark = -1;  /* CDMAStationClassMark */
static int hf_ansi_map_cdmaStationClassMark2 = -1;  /* CDMAStationClassMark2 */
static int hf_ansi_map_cdmaTargetMAHOList = -1;   /* CDMATargetMAHOList */
static int hf_ansi_map_cdmaTargetMeasurementList = -1;  /* CDMATargetMeasurementList */
static int hf_ansi_map_dataPrivacyParameters = -1;  /* DataPrivacyParameters */
static int hf_ansi_map_ilspInformation = -1;      /* ISLPInformation */
static int hf_ansi_map_msLocation = -1;           /* MSLocation */
static int hf_ansi_map_nampsCallMode = -1;        /* NAMPSCallMode */
static int hf_ansi_map_nampsChannelData = -1;     /* NAMPSChannelData */
static int hf_ansi_map_nonPublicData = -1;        /* NonPublicData */
static int hf_ansi_map_pdsnAddress = -1;          /* PDSNAddress */
static int hf_ansi_map_pdsnProtocolType = -1;     /* PDSNProtocolType */
static int hf_ansi_map_qosPriority = -1;          /* QoSPriority */
static int hf_ansi_map_systemOperatorCode = -1;   /* SystemOperatorCode */
static int hf_ansi_map_tdmaBandwidth = -1;        /* TDMABandwidth */
static int hf_ansi_map_tdmaServiceCode = -1;      /* TDMAServiceCode */
static int hf_ansi_map_tdmaTerminalCapability = -1;  /* TDMATerminalCapability */
static int hf_ansi_map_tdmaVoiceCoder = -1;       /* TDMAVoiceCoder */
static int hf_ansi_map_userZoneData = -1;         /* UserZoneData */
static int hf_ansi_map_bsmcstatus = -1;           /* BSMCStatus */
static int hf_ansi_map_cdma2000HandoffResponseIOSData = -1;  /* CDMA2000HandoffResponseIOSData */
static int hf_ansi_map_cdmaCodeChannelList = -1;  /* CDMACodeChannelList */
static int hf_ansi_map_cdmaSearchParameters = -1;  /* CDMASearchParameters */
static int hf_ansi_map_cdmaSearchWindow = -1;     /* CDMASearchWindow */
static int hf_ansi_map_sOCStatus = -1;            /* SOCStatus */
static int hf_ansi_map_releaseReason = -1;        /* ReleaseReason */
static int hf_ansi_map_acgencountered = -1;       /* ACGEncountered */
static int hf_ansi_map_callingPartyName = -1;     /* CallingPartyName */
static int hf_ansi_map_callingPartyNumberDigits1 = -1;  /* CallingPartyNumberDigits1 */
static int hf_ansi_map_callingPartyNumberDigits2 = -1;  /* CallingPartyNumberDigits2 */
static int hf_ansi_map_callingPartySubaddress = -1;  /* CallingPartySubaddress */
static int hf_ansi_map_conferenceCallingIndicator = -1;  /* ConferenceCallingIndicator */
static int hf_ansi_map_mobileDirectoryNumber = -1;  /* MobileDirectoryNumber */
static int hf_ansi_map_mSCIdentificationNumber = -1;  /* MSCIdentificationNumber */
static int hf_ansi_map_oneTimeFeatureIndicator = -1;  /* OneTimeFeatureIndicator */
static int hf_ansi_map_featureResult = -1;        /* FeatureResult */
static int hf_ansi_map_accessDeniedReason = -1;   /* AccessDeniedReason */
static int hf_ansi_map_actionCode = -1;           /* ActionCode */
static int hf_ansi_map_announcementList = -1;     /* AnnouncementList */
static int hf_ansi_map_callingPartyNumberString1 = -1;  /* CallingPartyNumberString1 */
static int hf_ansi_map_callingPartyNumberString2 = -1;  /* CallingPartyNumberString2 */
static int hf_ansi_map_digits_Destination = -1;   /* Digits */
static int hf_ansi_map_displayText = -1;          /* DisplayText */
static int hf_ansi_map_displayText2 = -1;         /* DisplayText2 */
static int hf_ansi_map_dmh_AccountCodeDigits = -1;  /* DMH_AccountCodeDigits */
static int hf_ansi_map_dmh_AlternateBillingDigits = -1;  /* DMH_AlternateBillingDigits */
static int hf_ansi_map_dmh_BillingDigits = -1;    /* DMH_BillingDigits */
static int hf_ansi_map_dmh_RedirectionIndicator = -1;  /* DMH_RedirectionIndicator */
static int hf_ansi_map_groupInformation = -1;     /* GroupInformation */
static int hf_ansi_map_noAnswerTime = -1;         /* NoAnswerTime */
static int hf_ansi_map_pACAIndicator = -1;        /* PACAIndicator */
static int hf_ansi_map_pilotNumber = -1;          /* PilotNumber */
static int hf_ansi_map_preferredLanguageIndicator = -1;  /* PreferredLanguageIndicator */
static int hf_ansi_map_redirectingNumberDigits = -1;  /* RedirectingNumberDigits */
static int hf_ansi_map_redirectingNumberString = -1;  /* RedirectingNumberString */
static int hf_ansi_map_redirectingSubaddress = -1;  /* RedirectingSubaddress */
static int hf_ansi_map_resumePIC = -1;            /* ResumePIC */
static int hf_ansi_map_terminationList = -1;      /* TerminationList */
static int hf_ansi_map_terminationTriggers = -1;  /* TerminationTriggers */
static int hf_ansi_map_triggerAddressList = -1;   /* TriggerAddressList */
static int hf_ansi_map_targetCellIDList = -1;     /* TargetCellIDList */
static int hf_ansi_map_signalQuality = -1;        /* SignalQuality */
static int hf_ansi_map_targetMeasurementList = -1;  /* TargetMeasurementList */
static int hf_ansi_map_alertResult = -1;          /* AlertResult */
static int hf_ansi_map_messageWaitingNotificationCount = -1;  /* MessageWaitingNotificationCount */
static int hf_ansi_map_messageWaitingNotificationType = -1;  /* MessageWaitingNotificationType */
static int hf_ansi_map_cdmaBandClass = -1;        /* CDMABandClass */
static int hf_ansi_map_cdmaServiceOption = -1;    /* CDMAServiceOption */
static int hf_ansi_map_cdmaSlotCycleIndex = -1;   /* CDMASlotCycleIndex */
static int hf_ansi_map_extendedMSCID = -1;        /* ExtendedMSCID */
static int hf_ansi_map_extendedSystemMyTypeCode = -1;  /* ExtendedSystemMyTypeCode */
static int hf_ansi_map_imsi = -1;                 /* IMSI */
static int hf_ansi_map_legInformation = -1;       /* LegInformation */
static int hf_ansi_map_mSIDUsage = -1;            /* MSIDUsage */
static int hf_ansi_map_networkTMSI = -1;          /* NetworkTMSI */
static int hf_ansi_map_pageCount = -1;            /* PageCount */
static int hf_ansi_map_pageIndicator = -1;        /* PageIndicator */
static int hf_ansi_map_pageResponseTime = -1;     /* PageResponseTime */
static int hf_ansi_map_pilotBillingID = -1;       /* PilotBillingID */
static int hf_ansi_map_redirectingPartyName = -1;  /* RedirectingPartyName */
static int hf_ansi_map_systemMyTypeCode = -1;     /* SystemMyTypeCode */
static int hf_ansi_map_tdmaDataFeaturesIndicator = -1;  /* TDMADataFeaturesIndicator */
static int hf_ansi_map_terminationTreatment = -1;  /* TerminationTreatment */
static int hf_ansi_map_conditionallyDeniedReason = -1;  /* ConditionallyDeniedReason */
static int hf_ansi_map_pagingFrameClass = -1;     /* PagingFrameClass */
static int hf_ansi_map_pSID_RSIDList = -1;        /* PSID_RSIDList */
static int hf_ansi_map_randc = -1;                /* RANDC */
static int hf_ansi_map_tdmaDataMode = -1;         /* TDMADataMode */
static int hf_ansi_map_changeServiceAttributes = -1;  /* ChangeServiceAttributes */
static int hf_ansi_map_edirectingSubaddress = -1;  /* RedirectingSubaddress */
static int hf_ansi_map_setupResult = -1;          /* SetupResult */
static int hf_ansi_map_terminationAccessType = -1;  /* TerminationAccessType */
static int hf_ansi_map_triggerType = -1;          /* TriggerType */
static int hf_ansi_map_winCapability = -1;        /* WINCapability */
static int hf_ansi_map_callingPartyCategory = -1;  /* CallingPartyCategory */
static int hf_ansi_map_controlNetworkID = -1;     /* ControlNetworkID */
static int hf_ansi_map_digits_carrier = -1;       /* Digits */
static int hf_ansi_map_digits_dest = -1;          /* Digits */
static int hf_ansi_map_dmh_ServiceID = -1;        /* DMH_ServiceID */
static int hf_ansi_map_edirectingNumberDigits = -1;  /* RedirectingNumberDigits */
static int hf_ansi_map_lectronicSerialNumber = -1;  /* ElectronicSerialNumber */
static int hf_ansi_map_deregistrationType = -1;   /* DeregistrationType */
static int hf_ansi_map_servicesResult = -1;       /* ServicesResult */
static int hf_ansi_map_sms_MessageWaitingIndicator = -1;  /* SMS_MessageWaitingIndicator */
static int hf_ansi_map_originationTriggers = -1;  /* OriginationTriggers */
static int hf_ansi_map_featureIndicator = -1;     /* FeatureIndicator */
static int hf_ansi_map_dmh_ChargeInformation = -1;  /* DMH_ChargeInformation */
static int hf_ansi_map_qualificationInformationCode = -1;  /* QualificationInformationCode */
static int hf_ansi_map_authorizationDenied = -1;  /* AuthorizationDenied */
static int hf_ansi_map_authorizationPeriod = -1;  /* AuthorizationPeriod */
static int hf_ansi_map_deniedAuthorizationPeriod = -1;  /* DeniedAuthorizationPeriod */
static int hf_ansi_map_randValidTime = -1;        /* RANDValidTime */
static int hf_ansi_map_redirectionReason = -1;    /* RedirectionReason */
static int hf_ansi_map_cancellationType = -1;     /* CancellationType */
static int hf_ansi_map_controlChannelData = -1;   /* ControlChannelData */
static int hf_ansi_map_receivedSignalQuality = -1;  /* ReceivedSignalQuality */
static int hf_ansi_map_systemAccessData = -1;     /* SystemAccessData */
static int hf_ansi_map_cancellationDenied = -1;   /* CancellationDenied */
static int hf_ansi_map_availabilityType = -1;     /* AvailabilityType */
static int hf_ansi_map_borderCellAccess = -1;     /* BorderCellAccess */
static int hf_ansi_map_msc_Address = -1;          /* MSC_Address */
static int hf_ansi_map_sms_Address = -1;          /* SMS_Address */
static int hf_ansi_map_digits_Carrier = -1;       /* Digits */
static int hf_ansi_map_authenticationCapability = -1;  /* AuthenticationCapability */
static int hf_ansi_map_callingFeaturesIndicator = -1;  /* CallingFeaturesIndicator */
static int hf_ansi_map_geographicAuthorization = -1;  /* GeographicAuthorization */
static int hf_ansi_map_originationIndicator = -1;  /* OriginationIndicator */
static int hf_ansi_map_restrictionDigits = -1;    /* RestrictionDigits */
static int hf_ansi_map_sms_OriginationRestrictions = -1;  /* SMS_OriginationRestrictions */
static int hf_ansi_map_sms_TerminationRestrictions = -1;  /* SMS_TerminationRestrictions */
static int hf_ansi_map_spinipin = -1;             /* SPINIPIN */
static int hf_ansi_map_spiniTriggers = -1;        /* SPINITriggers */
static int hf_ansi_map_terminationRestrictionCode = -1;  /* TerminationRestrictionCode */
static int hf_ansi_map_digitCollectionControl = -1;  /* DigitCollectionControl */
static int hf_ansi_map_trunkStatus = -1;          /* TrunkStatus */
static int hf_ansi_map_userGroup = -1;            /* UserGroup */
static int hf_ansi_map_voiceMailboxNumber = -1;   /* VoiceMailboxNumber */
static int hf_ansi_map_voiceMailboxPIN = -1;      /* VoiceMailboxPIN */
static int hf_ansi_map_sms_BearerData = -1;       /* SMS_BearerData */
static int hf_ansi_map_sms_TeleserviceIdentifier = -1;  /* SMS_TeleserviceIdentifier */
static int hf_ansi_map_sms_ChargeIndicator = -1;  /* SMS_ChargeIndicator */
static int hf_ansi_map_sms_DestinationAddress = -1;  /* SMS_DestinationAddress */
static int hf_ansi_map_sms_OriginalDestinationAddress = -1;  /* SMS_OriginalDestinationAddress */
static int hf_ansi_map_sms_OriginalDestinationSubaddress = -1;  /* SMS_OriginalDestinationSubaddress */
static int hf_ansi_map_sms_OriginalOriginatingAddress = -1;  /* SMS_OriginalOriginatingAddress */
static int hf_ansi_map_sms_OriginalOriginatingSubaddress = -1;  /* SMS_OriginalOriginatingSubaddress */
static int hf_ansi_map_sms_OriginatingAddress = -1;  /* SMS_OriginatingAddress */
static int hf_ansi_map_sms_CauseCode = -1;        /* SMS_CauseCode */
static int hf_ansi_map_interMessageTime = -1;     /* InterMessageTime */
static int hf_ansi_map_newlyAssignedMIN = -1;     /* NewlyAssignedMIN */
static int hf_ansi_map_newlyAssignedIMSI = -1;    /* NewlyAssignedIMSI */
static int hf_ansi_map_newMINExtension = -1;      /* NewMINExtension */
static int hf_ansi_map_sms_MessageCount = -1;     /* SMS_MessageCount */
static int hf_ansi_map_sms_NotificationIndicator = -1;  /* SMS_NotificationIndicator */
static int hf_ansi_map_temporaryReferenceNumber = -1;  /* TemporaryReferenceNumber */
static int hf_ansi_map_mobileStationMSID = -1;    /* MobileStationMSID */
static int hf_ansi_map_sms_AccessDeniedReason = -1;  /* SMS_AccessDeniedReason */
static int hf_ansi_map_seizureType = -1;          /* SeizureType */
static int hf_ansi_map_requiredParametersMask = -1;  /* RequiredParametersMask */
static int hf_ansi_map_reasonList = -1;           /* ReasonList */
static int hf_ansi_map_networkTMSIExpirationTime = -1;  /* NetworkTMSIExpirationTime */
static int hf_ansi_map_newNetworkTMSI = -1;       /* NewNetworkTMSI */
static int hf_ansi_map_serviceID = -1;            /* ServiceID */
static int hf_ansi_map_dataAccessElementList = -1;  /* DataAccessElementList */
static int hf_ansi_map_timeDateOffset = -1;       /* TimeDateOffset */
static int hf_ansi_map_timeOfDay = -1;            /* TimeOfDay */
static int hf_ansi_map_dmd_BillingIndicator = -1;  /* DMH_BillingIndicator */
static int hf_ansi_map_failureType = -1;          /* FailureType */
static int hf_ansi_map_failureCause = -1;         /* FailureCause */
static int hf_ansi_map_outingDigits = -1;         /* RoutingDigits */
static int hf_ansi_map_databaseKey = -1;          /* DatabaseKey */
static int hf_ansi_map_modificationRequestList = -1;  /* ModificationRequestList */
static int hf_ansi_map_modificationResultList = -1;  /* ModificationResultList */
static int hf_ansi_map_serviceDataAccessElementList = -1;  /* ServiceDataAccessElementList */
static int hf_ansi_map_privateSpecializedResource = -1;  /* PrivateSpecializedResource */
static int hf_ansi_map_specializedResource = -1;  /* SpecializedResource */
static int hf_ansi_map_executeScript = -1;        /* ExecuteScript */
static int hf_ansi_map_scriptResult = -1;         /* ScriptResult */
static int hf_ansi_map_tdmaVoiceMode = -1;        /* TDMAVoiceMode */
static int hf_ansi_map_callStatus = -1;           /* CallStatus */
static int hf_ansi_map_releaseCause = -1;         /* ReleaseCause */
static int hf_ansi_map_callRecoveryIDList = -1;   /* CallRecoveryIDList */
static int hf_ansi_map_positionInformationCode = -1;  /* PositionInformationCode */
static int hf_ansi_map_mSStatus = -1;             /* MSStatus */
static int hf_ansi_map_pSID_RSIDInformation = -1;  /* PSID_RSIDInformation */
static int hf_ansi_map_controlType = -1;          /* ControlType */
static int hf_ansi_map_destinationAddress = -1;   /* DestinationAddress */
static int hf_ansi_map_gapDuration = -1;          /* GapDuration */
static int hf_ansi_map_gapInterval = -1;          /* GapInterval */
static int hf_ansi_map_invokingNEType = -1;       /* InvokingNEType */
static int hf_ansi_map_range = -1;                /* Range */
static int hf_ansi_map_ctionCode = -1;            /* ActionCode */
static int hf_ansi_map_aKeyProtocolVersion = -1;  /* AKeyProtocolVersion */
static int hf_ansi_map_mobileStationPartialKey = -1;  /* MobileStationPartialKey */
static int hf_ansi_map_newlyAssignedMSID = -1;    /* NewlyAssignedMSID */
static int hf_ansi_map_baseStationPartialKey = -1;  /* BaseStationPartialKey */
static int hf_ansi_map_modulusValue = -1;         /* ModulusValue */
static int hf_ansi_map_otasp_ResultCode = -1;     /* OTASP_ResultCode */
static int hf_ansi_map_primitiveValue = -1;       /* PrimitiveValue */
static int hf_ansi_map_announcementCode1 = -1;    /* AnnouncementCode */
static int hf_ansi_map_announcementCode2 = -1;    /* AnnouncementCode */
static int hf_ansi_map_cdmaCodeChannel = -1;      /* CDMACodeChannel */
static int hf_ansi_map_cdmaPilotPN = -1;          /* CDMAPilotPN */
static int hf_ansi_map_cdmaPowerCombinedIndicator = -1;  /* CDMAPowerCombinedIndicator */
static int hf_ansi_map_CDMACodeChannelList_item = -1;  /* CDMACodeChannelInformation */
static int hf_ansi_map_cdmaPilotStrength = -1;    /* CDMAPilotStrength */
static int hf_ansi_map_cdmaTargetOneWayDelay = -1;  /* CDMATargetOneWayDelay */
static int hf_ansi_map_CDMATargetMAHOList_item = -1;  /* CDMATargetMAHOInformation */
static int hf_ansi_map_cdmaSignalQuality = -1;    /* CDMASignalQuality */
static int hf_ansi_map_CDMATargetMeasurementList_item = -1;  /* CDMATargetMeasurementInformation */
static int hf_ansi_map_TargetMeasurementList_item = -1;  /* TargetMeasurementInformation */
static int hf_ansi_map_TerminationList_item = -1;  /* TerminationList_item */
static int hf_ansi_map_intersystemTermination = -1;  /* IntersystemTermination */
static int hf_ansi_map_localTermination = -1;     /* LocalTermination */
static int hf_ansi_map_pstnTermination = -1;      /* PSTNTermination */
static int hf_ansi_map_CDMAServiceOptionList_item = -1;  /* CDMAServiceOption */
static int hf_ansi_map_pSID_RSIDInformation1 = -1;  /* PSID_RSIDInformation */
static int hf_ansi_map_targetCellID1 = -1;        /* TargetCellID */
static int hf_ansi_map_cdmaConnectionReference = -1;  /* CDMAConnectionReference */
static int hf_ansi_map_cdmaState = -1;            /* CDMAState */
static int hf_ansi_map_cdmaServiceOptionConnectionIdentifier = -1;  /* CDMAServiceOptionConnectionIdentifier */
static int hf_ansi_map_CDMAConnectionReferenceList_item = -1;  /* CDMAConnectionReferenceList_item */
static int hf_ansi_map_cdmaConnectionReferenceInformation = -1;  /* CDMAConnectionReferenceInformation */
static int hf_ansi_map_cdmaConnectionReferenceInformation2 = -1;  /* CDMAConnectionReferenceInformation */
static int hf_ansi_map_analogRedirectInfo = -1;   /* AnalogRedirectInfo */
static int hf_ansi_map_CDMAChannelNumberList_item = -1;  /* CDMAChannelNumberList_item */
static int hf_ansi_map_cdmaChannelNumber = -1;    /* CDMAChannelNumber */
static int hf_ansi_map_cdmaChannelNumber2 = -1;   /* CDMAChannelNumber */
static int hf_ansi_map_cdmaChannelNumberList = -1;  /* CDMAChannelNumberList */
static int hf_ansi_map_dataID = -1;               /* DataID */
static int hf_ansi_map_change = -1;               /* Change */
static int hf_ansi_map_dataValue = -1;            /* DataValue */
static int hf_ansi_map_DataAccessElementList_item = -1;  /* DataAccessElementList_item */
static int hf_ansi_map_dataAccessElement1 = -1;   /* DataAccessElement */
static int hf_ansi_map_dataAccessElement2 = -1;   /* DataAccessElement */
static int hf_ansi_map_dataResult = -1;           /* DataResult */
static int hf_ansi_map_DataUpdateResultList_item = -1;  /* DataUpdateResult */
static int hf_ansi_map_globalTitle = -1;          /* GlobalTitle */
static int hf_ansi_map_pC_SSN = -1;               /* PC_SSN */
static int hf_ansi_map_scriptName = -1;           /* ScriptName */
static int hf_ansi_map_scriptArgument = -1;       /* ScriptArgument */
static int hf_ansi_map_allOrNone = -1;            /* AllOrNone */
static int hf_ansi_map_ModificationRequestList_item = -1;  /* ModificationRequest */
static int hf_ansi_map_serviceDataResultList = -1;  /* ServiceDataResultList */
static int hf_ansi_map_ModificationResultList_item = -1;  /* ModificationResult */
static int hf_ansi_map_ServiceDataAccessElementList_item = -1;  /* ServiceDataAccessElement */
static int hf_ansi_map_dataUpdateResultList = -1;  /* DataUpdateResultList */
static int hf_ansi_map_ServiceDataResultList_item = -1;  /* ServiceDataResult */
static int hf_ansi_map_TriggerAddressList_item = -1;  /* TriggerAddressList_item */
static int hf_ansi_map_triggerList = -1;          /* TriggerList */
static int hf_ansi_map_triggerListOpt = -1;       /* TriggerList */
static int hf_ansi_map_wIN_TriggerList = -1;      /* WIN_TriggerList */
static int hf_ansi_map_triggerCapability = -1;    /* TriggerCapability */
static int hf_ansi_map_wINOperationsCapability = -1;  /* WINOperationsCapability */
static int hf_ansi_map_detectionPointType = -1;   /* DetectionPointType */
static int hf_ansi_map_WIN_TriggerList_item = -1;  /* WIN_Trigger */
static int hf_ansi_map_CallRecoveryIDList_item = -1;  /* CallRecoveryID */
static int hf_ansi_map_sCFOverloadGapInterval = -1;  /* SCFOverloadGapInterval */
static int hf_ansi_map_serviceManagementSystemGapInterval = -1;  /* ServiceManagementSystemGapInterval */
static int hf_ansi_map_mobileStationIMSI = -1;    /* MobileStationIMSI */
static int hf_ansi_map_handoffMeasurementRequest = -1;  /* HandoffMeasurementRequest */
static int hf_ansi_map_facilitiesDirective = -1;  /* FacilitiesDirective */
static int hf_ansi_map_handoffBack = -1;          /* HandoffBack */
static int hf_ansi_map_facilitiesRelease = -1;    /* FacilitiesRelease */
static int hf_ansi_map_qualificationRequest = -1;  /* QualificationRequest */
static int hf_ansi_map_qualificationDirective = -1;  /* QualificationDirective */
static int hf_ansi_map_blocking = -1;             /* Blocking */
static int hf_ansi_map_unblocking = -1;           /* Unblocking */
static int hf_ansi_map_resetCircuit = -1;         /* ResetCircuit */
static int hf_ansi_map_trunkTest = -1;            /* TrunkTest */
static int hf_ansi_map_trunkTestDisconnect = -1;  /* TrunkTestDisconnect */
static int hf_ansi_map_registrationNotification = -1;  /* RegistrationNotification */
static int hf_ansi_map_registrationCancellation = -1;  /* RegistrationCancellation */
static int hf_ansi_map_locationRequest = -1;      /* LocationRequest */
static int hf_ansi_map_routingRequest = -1;       /* RoutingRequest */
static int hf_ansi_map_featureRequest = -1;       /* FeatureRequest */
static int hf_ansi_map_unreliableRoamerDataDirective = -1;  /* UnreliableRoamerDataDirective */
static int hf_ansi_map_mSInactive = -1;           /* MSInactive */
static int hf_ansi_map_transferToNumberRequest = -1;  /* TransferToNumberRequest */
static int hf_ansi_map_redirectionRequest = -1;   /* RedirectionRequest */
static int hf_ansi_map_handoffToThird = -1;       /* HandoffToThird */
static int hf_ansi_map_flashRequest = -1;         /* FlashRequest */
static int hf_ansi_map_authenticationDirective = -1;  /* AuthenticationDirective */
static int hf_ansi_map_authenticationRequest = -1;  /* AuthenticationRequest */
static int hf_ansi_map_baseStationChallenge = -1;  /* BaseStationChallenge */
static int hf_ansi_map_authenticationFailureReport = -1;  /* AuthenticationFailureReport */
static int hf_ansi_map_countRequest = -1;         /* CountRequest */
static int hf_ansi_map_interSystemPage = -1;      /* InterSystemPage */
static int hf_ansi_map_unsolicitedResponse = -1;  /* UnsolicitedResponse */
static int hf_ansi_map_bulkDeregistration = -1;   /* BulkDeregistration */
static int hf_ansi_map_handoffMeasurementRequest2 = -1;  /* HandoffMeasurementRequest2 */
static int hf_ansi_map_facilitiesDirective2 = -1;  /* FacilitiesDirective2 */
static int hf_ansi_map_handoffBack2 = -1;         /* HandoffBack2 */
static int hf_ansi_map_handoffToThird2 = -1;      /* HandoffToThird2 */
static int hf_ansi_map_authenticationDirectiveForward = -1;  /* AuthenticationDirectiveForward */
static int hf_ansi_map_authenticationStatusReport = -1;  /* AuthenticationStatusReport */
static int hf_ansi_map_informationDirective = -1;  /* InformationDirective */
static int hf_ansi_map_informationForward = -1;   /* InformationForward */
static int hf_ansi_map_interSystemAnswer = -1;    /* InterSystemAnswer */
static int hf_ansi_map_interSystemPage2 = -1;     /* InterSystemPage2 */
static int hf_ansi_map_interSystemSetup = -1;     /* InterSystemSetup */
static int hf_ansi_map_originationRequest = -1;   /* OriginationRequest */
static int hf_ansi_map_randomVariableRequest = -1;  /* RandomVariableRequest */
static int hf_ansi_map_redirectionDirective = -1;  /* RedirectionDirective */
static int hf_ansi_map_remoteUserInteractionDirective = -1;  /* RemoteUserInteractionDirective */
static int hf_ansi_map_sMSDeliveryBackward = -1;  /* SMSDeliveryBackward */
static int hf_ansi_map_sMSDeliveryForward = -1;   /* SMSDeliveryForward */
static int hf_ansi_map_sMSDeliveryPointToPoint = -1;  /* SMSDeliveryPointToPoint */
static int hf_ansi_map_sMSNotification = -1;      /* SMSNotification */
static int hf_ansi_map_sMSRequest = -1;           /* SMSRequest */
static int hf_ansi_map_oTASPRequest = -1;         /* OTASPRequest */
static int hf_ansi_map_changeFacilities = -1;     /* ChangeFacilities */
static int hf_ansi_map_changeService = -1;        /* ChangeService */
static int hf_ansi_map_parameterRequest = -1;     /* ParameterRequest */
static int hf_ansi_map_tMSIDirective = -1;        /* TMSIDirective */
static int hf_ansi_map_serviceRequest = -1;       /* ServiceRequest */
static int hf_ansi_map_analyzedInformation = -1;  /* AnalyzedInformation */
static int hf_ansi_map_connectionFailureReport = -1;  /* ConnectionFailureReport */
static int hf_ansi_map_connectResource = -1;      /* ConnectResource */
static int hf_ansi_map_facilitySelectedAndAvailable = -1;  /* FacilitySelectedAndAvailable */
static int hf_ansi_map_modify = -1;               /* Modify */
static int hf_ansi_map_search = -1;               /* Search */
static int hf_ansi_map_seizeResource = -1;        /* SeizeResource */
static int hf_ansi_map_sRFDirective = -1;         /* SRFDirective */
static int hf_ansi_map_tBusy = -1;                /* TBusy */
static int hf_ansi_map_tNoAnswer = -1;            /* TNoAnswer */
static int hf_ansi_map_messageDirective = -1;     /* MessageDirective */
static int hf_ansi_map_bulkDisconnection = -1;    /* BulkDisconnection */
static int hf_ansi_map_callControlDirective = -1;  /* CallControlDirective */
static int hf_ansi_map_oAnswer = -1;              /* OAnswer */
static int hf_ansi_map_oDisconnect = -1;          /* ODisconnect */
static int hf_ansi_map_callRecoveryReport = -1;   /* CallRecoveryReport */
static int hf_ansi_map_tAnswer = -1;              /* TAnswer */
static int hf_ansi_map_tDisconnect = -1;          /* TDisconnect */
static int hf_ansi_map_unreliableCallData = -1;   /* UnreliableCallData */
static int hf_ansi_map_oCalledPartyBusy = -1;     /* OCalledPartyBusy */
static int hf_ansi_map_oNoAnswer = -1;            /* ONoAnswer */
static int hf_ansi_map_positionRequest = -1;      /* PositionRequest */
static int hf_ansi_map_positionRequestForward = -1;  /* PositionRequestForward */
static int hf_ansi_map_aCGDirective = -1;         /* ACGDirective */
static int hf_ansi_map_roamerDatabaseVerificationRequest = -1;  /* RoamerDatabaseVerificationRequest */
static int hf_ansi_map_addService = -1;           /* AddService */
static int hf_ansi_map_dropService = -1;          /* DropService */
static int hf_ansi_map_handoffMeasurementRequestRes = -1;  /* HandoffMeasurementRequestRes */
static int hf_ansi_map_facilitiesDirectiveRes = -1;  /* FacilitiesDirectiveRes */
static int hf_ansi_map_handoffBackRes = -1;       /* HandoffBackRes */
static int hf_ansi_map_facilitiesReleaseRes = -1;  /* FacilitiesReleaseRes */
static int hf_ansi_map_qualificationRequestRes = -1;  /* QualificationRequestRes */
static int hf_ansi_map_resetCircuitRes = -1;      /* ResetCircuitRes */
static int hf_ansi_map_registrationNotificationRes = -1;  /* RegistrationNotificationRes */
static int hf_ansi_map_registrationCancellationRes = -1;  /* RegistrationCancellationRes */
static int hf_ansi_map_locationRequestRes = -1;   /* LocationRequestRes */
static int hf_ansi_map_routingRequestRes = -1;    /* RoutingRequestRes */
static int hf_ansi_map_featureRequestRes = -1;    /* FeatureRequestRes */
static int hf_ansi_map_transferToNumberRequestRes = -1;  /* TransferToNumberRequestRes */
static int hf_ansi_map_handoffToThirdRes = -1;    /* HandoffToThirdRes */
static int hf_ansi_map_authenticationDirectiveRes = -1;  /* AuthenticationDirectiveRes */
static int hf_ansi_map_authenticationRequestRes = -1;  /* AuthenticationRequestRes */
static int hf_ansi_map_authenticationFailureReportRes = -1;  /* AuthenticationFailureReportRes */
static int hf_ansi_map_countRequestRes = -1;      /* CountRequestRes */
static int hf_ansi_map_interSystemPageRes = -1;   /* InterSystemPageRes */
static int hf_ansi_map_unsolicitedResponseRes = -1;  /* UnsolicitedResponseRes */
static int hf_ansi_map_handoffMeasurementRequest2Res = -1;  /* HandoffMeasurementRequest2Res */
static int hf_ansi_map_facilitiesDirective2Res = -1;  /* FacilitiesDirective2Res */
static int hf_ansi_map_handoffBack2Res = -1;      /* HandoffBack2Res */
static int hf_ansi_map_handoffToThird2Res = -1;   /* HandoffToThird2Res */
static int hf_ansi_map_authenticationDirectiveForwardRes = -1;  /* AuthenticationDirectiveForwardRes */
static int hf_ansi_map_authenticationStatusReportRes = -1;  /* AuthenticationStatusReportRes */
static int hf_ansi_map_informationForwardRes = -1;  /* InformationForwardRes */
static int hf_ansi_map_interSystemPage2Res = -1;  /* InterSystemPage2Res */
static int hf_ansi_map_interSystemSetupRes = -1;  /* InterSystemSetupRes */
static int hf_ansi_map_originationRequestRes = -1;  /* OriginationRequestRes */
static int hf_ansi_map_randomVariableRequestRes = -1;  /* RandomVariableRequestRes */
static int hf_ansi_map_remoteUserInteractionDirectiveRes = -1;  /* RemoteUserInteractionDirectiveRes */
static int hf_ansi_map_sMSDeliveryBackwardRes = -1;  /* SMSDeliveryBackwardRes */
static int hf_ansi_map_sMSDeliveryForwardRes = -1;  /* SMSDeliveryForwardRes */
static int hf_ansi_map_sMSDeliveryPointToPointRes = -1;  /* SMSDeliveryPointToPointRes */
static int hf_ansi_map_sMSNotificationRes = -1;   /* SMSNotificationRes */
static int hf_ansi_map_sMSRequestRes = -1;        /* SMSRequestRes */
static int hf_ansi_map_oTASPRequestRes = -1;      /* OTASPRequestRes */
static int hf_ansi_map_changeFacilitiesRes = -1;  /* ChangeFacilitiesRes */
static int hf_ansi_map_changeServiceRes = -1;     /* ChangeServiceRes */
static int hf_ansi_map_parameterRequestRes = -1;  /* ParameterRequestRes */
static int hf_ansi_map_tMSIDirectiveRes = -1;     /* TMSIDirectiveRes */
static int hf_ansi_map_serviceRequestRes = -1;    /* ServiceRequestRes */
static int hf_ansi_map_analyzedInformationRes = -1;  /* AnalyzedInformationRes */
static int hf_ansi_map_facilitySelectedAndAvailableRes = -1;  /* FacilitySelectedAndAvailableRes */
static int hf_ansi_map_modifyRes = -1;            /* ModifyRes */
static int hf_ansi_map_searchRes = -1;            /* SearchRes */
static int hf_ansi_map_seizeResourceRes = -1;     /* SeizeResourceRes */
static int hf_ansi_map_sRFDirectiveRes = -1;      /* SRFDirectiveRes */
static int hf_ansi_map_tBusyRes = -1;             /* TBusyRes */
static int hf_ansi_map_tNoAnswerRes = -1;         /* TNoAnswerRes */
static int hf_ansi_map_callControlDirectiveRes = -1;  /* CallControlDirectiveRes */
static int hf_ansi_map_oDisconnectRes = -1;       /* ODisconnectRes */
static int hf_ansi_map_tDisconnectRes = -1;       /* TDisconnectRes */
static int hf_ansi_map_oCalledPartyBusyRes = -1;  /* OCalledPartyBusyRes */
static int hf_ansi_map_oNoAnswerRes = -1;         /* ONoAnswerRes */
static int hf_ansi_map_positionRequestRes = -1;   /* PositionRequestRes */
static int hf_ansi_map_positionRequestForwardRes = -1;  /* PositionRequestForwardRes */
static int hf_ansi_map_roamerDatabaseVerificationRequestRes = -1;  /* RoamerDatabaseVerificationRequestRes */
static int hf_ansi_map_addServiceRes = -1;        /* AddServiceRes */
static int hf_ansi_map_dropServiceRes = -1;       /* DropServiceRes */

/*--- End of included file: packet-ansi_map-hf.c ---*/
#line 317 "packet-ansi_map-template.c"

/* Initialize the subtree pointers */
static gint ett_ansi_map = -1;
static gint ett_mintype = -1;
static gint ett_digitstype = -1;
static gint ett_billingid = -1;
static gint ett_sms_bearer_data = -1;
static gint ett_sms_teleserviceIdentifier = -1;
static gint ett_extendedmscid = -1;
static gint ett_extendedsystemmytypecode = -1;
static gint ett_handoffstate = -1;
static gint ett_mscid = -1;
static gint ett_cdmachanneldata = -1;
static gint ett_cdmastationclassmark = -1;
static gint ett_channeldata = -1;
static gint ett_confidentialitymodes = -1;
static gint ett_CDMA2000HandoffInvokeIOSData = -1;
static gint ett_CDMA2000HandoffResponseIOSData = -1;
static gint ett_originationtriggers = -1;
static gint ett_pacaindicator = -1;
static gint ett_callingpartyname = -1;
static gint ett_triggercapability = -1;
static gint ett_winoperationscapability = -1;
static gint ett_controlnetworkid = -1;
static gint ett_transactioncapability = -1;
static gint ett_cdmaserviceoption = -1;
static gint ett_systemcapabilities = -1;


/*--- Included file: packet-ansi_map-ett.c ---*/
#line 1 "packet-ansi_map-ett.c"
static gint ett_ansi_map_ComponentPDU = -1;
static gint ett_ansi_map_InvokePDU = -1;
static gint ett_ansi_map_ReturnResultPDU = -1;
static gint ett_ansi_map_ReturnErrorPDU = -1;
static gint ett_ansi_map_RejectPDU = -1;
static gint ett_ansi_map_OperationCode = -1;
static gint ett_ansi_map_ErrorCode = -1;
static gint ett_ansi_map_AuthenticationDirective = -1;
static gint ett_ansi_map_AuthenticationDirectiveRes = -1;
static gint ett_ansi_map_AuthenticationDirectiveForward = -1;
static gint ett_ansi_map_AuthenticationDirectiveForwardRes = -1;
static gint ett_ansi_map_AuthenticationFailureReport = -1;
static gint ett_ansi_map_AuthenticationFailureReportRes = -1;
static gint ett_ansi_map_AuthenticationRequest = -1;
static gint ett_ansi_map_AuthenticationRequestRes = -1;
static gint ett_ansi_map_AuthenticationStatusReport = -1;
static gint ett_ansi_map_AuthenticationStatusReportRes = -1;
static gint ett_ansi_map_BaseStationChallenge = -1;
static gint ett_ansi_map_BaseStationChallengeRes = -1;
static gint ett_ansi_map_Blocking = -1;
static gint ett_ansi_map_BulkDeregistration = -1;
static gint ett_ansi_map_CountRequest = -1;
static gint ett_ansi_map_CountRequestRes = -1;
static gint ett_ansi_map_FacilitiesDirective = -1;
static gint ett_ansi_map_FacilitiesDirectiveRes = -1;
static gint ett_ansi_map_FacilitiesDirective2 = -1;
static gint ett_ansi_map_FacilitiesDirective2Res = -1;
static gint ett_ansi_map_FacilitiesRelease = -1;
static gint ett_ansi_map_FacilitiesReleaseRes = -1;
static gint ett_ansi_map_FeatureRequest = -1;
static gint ett_ansi_map_FeatureRequestRes = -1;
static gint ett_ansi_map_FlashRequest = -1;
static gint ett_ansi_map_HandoffBack = -1;
static gint ett_ansi_map_HandoffBackRes = -1;
static gint ett_ansi_map_HandoffBack2 = -1;
static gint ett_ansi_map_HandoffBack2Res = -1;
static gint ett_ansi_map_HandoffMeasurementRequest = -1;
static gint ett_ansi_map_HandoffMeasurementRequestRes = -1;
static gint ett_ansi_map_HandoffMeasurementRequest2 = -1;
static gint ett_ansi_map_HandoffMeasurementRequest2Res = -1;
static gint ett_ansi_map_HandoffToThird = -1;
static gint ett_ansi_map_HandoffToThirdRes = -1;
static gint ett_ansi_map_HandoffToThird2 = -1;
static gint ett_ansi_map_HandoffToThird2Res = -1;
static gint ett_ansi_map_InformationDirective = -1;
static gint ett_ansi_map_InformationDirectiveRes = -1;
static gint ett_ansi_map_InformationForward = -1;
static gint ett_ansi_map_InformationForwardRes = -1;
static gint ett_ansi_map_InterSystemAnswer = -1;
static gint ett_ansi_map_InterSystemPage = -1;
static gint ett_ansi_map_InterSystemPageRes = -1;
static gint ett_ansi_map_InterSystemPage2 = -1;
static gint ett_ansi_map_InterSystemPage2Res = -1;
static gint ett_ansi_map_InterSystemSetup = -1;
static gint ett_ansi_map_InterSystemSetupRes = -1;
static gint ett_ansi_map_LocationRequest = -1;
static gint ett_ansi_map_LocationRequestRes = -1;
static gint ett_ansi_map_MSInactive = -1;
static gint ett_ansi_map_OriginationRequest = -1;
static gint ett_ansi_map_OriginationRequestRes = -1;
static gint ett_ansi_map_QualificationDirective = -1;
static gint ett_ansi_map_QualificationRequest = -1;
static gint ett_ansi_map_QualificationRequestRes = -1;
static gint ett_ansi_map_RandomVariableRequest = -1;
static gint ett_ansi_map_RandomVariableRequestRes = -1;
static gint ett_ansi_map_RedirectionDirective = -1;
static gint ett_ansi_map_RedirectionRequest = -1;
static gint ett_ansi_map_RegistrationCancellation = -1;
static gint ett_ansi_map_RegistrationCancellationRes = -1;
static gint ett_ansi_map_RegistrationNotification = -1;
static gint ett_ansi_map_RegistrationNotificationRes = -1;
static gint ett_ansi_map_RemoteUserInteractionDirective = -1;
static gint ett_ansi_map_RemoteUserInteractionDirectiveRes = -1;
static gint ett_ansi_map_ResetCircuit = -1;
static gint ett_ansi_map_ResetCircuitRes = -1;
static gint ett_ansi_map_RoutingRequest = -1;
static gint ett_ansi_map_RoutingRequestRes = -1;
static gint ett_ansi_map_SMSDeliveryBackward = -1;
static gint ett_ansi_map_SMSDeliveryBackwardRes = -1;
static gint ett_ansi_map_SMSDeliveryForward = -1;
static gint ett_ansi_map_SMSDeliveryForwardRes = -1;
static gint ett_ansi_map_SMSDeliveryPointToPoint = -1;
static gint ett_ansi_map_SMSDeliveryPointToPointRes = -1;
static gint ett_ansi_map_SMSNotification = -1;
static gint ett_ansi_map_SMSNotificationRes = -1;
static gint ett_ansi_map_SMSRequest = -1;
static gint ett_ansi_map_SMSRequestRes = -1;
static gint ett_ansi_map_TransferToNumberRequest = -1;
static gint ett_ansi_map_TransferToNumberRequestRes = -1;
static gint ett_ansi_map_TrunkTest = -1;
static gint ett_ansi_map_TrunkTestDisconnect = -1;
static gint ett_ansi_map_Unblocking = -1;
static gint ett_ansi_map_UnreliableRoamerDataDirective = -1;
static gint ett_ansi_map_UnsolicitedResponse = -1;
static gint ett_ansi_map_UnsolicitedResponseRes = -1;
static gint ett_ansi_map_ParameterRequest = -1;
static gint ett_ansi_map_ParameterRequestRes = -1;
static gint ett_ansi_map_TMSIDirective = -1;
static gint ett_ansi_map_TMSIDirectiveRes = -1;
static gint ett_ansi_map_NumberPortabilityRequest = -1;
static gint ett_ansi_map_ServiceRequest = -1;
static gint ett_ansi_map_ServiceRequestRes = -1;
static gint ett_ansi_map_AnalyzedInformation = -1;
static gint ett_ansi_map_AnalyzedInformationRes = -1;
static gint ett_ansi_map_ConnectionFailureReport = -1;
static gint ett_ansi_map_ConnectResource = -1;
static gint ett_ansi_map_FacilitySelectedAndAvailable = -1;
static gint ett_ansi_map_FacilitySelectedAndAvailableRes = -1;
static gint ett_ansi_map_Modify = -1;
static gint ett_ansi_map_ModifyRes = -1;
static gint ett_ansi_map_Search = -1;
static gint ett_ansi_map_SearchRes = -1;
static gint ett_ansi_map_SeizeResource = -1;
static gint ett_ansi_map_SeizeResourceRes = -1;
static gint ett_ansi_map_SRFDirective = -1;
static gint ett_ansi_map_SRFDirectiveRes = -1;
static gint ett_ansi_map_TBusy = -1;
static gint ett_ansi_map_TBusyRes = -1;
static gint ett_ansi_map_TNoAnswer = -1;
static gint ett_ansi_map_TNoAnswerRes = -1;
static gint ett_ansi_map_ChangeFacilities = -1;
static gint ett_ansi_map_ChangeFacilitiesRes = -1;
static gint ett_ansi_map_ChangeService = -1;
static gint ett_ansi_map_ChangeServiceRes = -1;
static gint ett_ansi_map_MessageDirective = -1;
static gint ett_ansi_map_BulkDisconnection = -1;
static gint ett_ansi_map_CallControlDirective = -1;
static gint ett_ansi_map_CallControlDirectiveRes = -1;
static gint ett_ansi_map_OAnswer = -1;
static gint ett_ansi_map_ODisconnect = -1;
static gint ett_ansi_map_ODisconnectRes = -1;
static gint ett_ansi_map_CallRecoveryReport = -1;
static gint ett_ansi_map_TAnswer = -1;
static gint ett_ansi_map_TDisconnect = -1;
static gint ett_ansi_map_TDisconnectRes = -1;
static gint ett_ansi_map_UnreliableCallData = -1;
static gint ett_ansi_map_OCalledPartyBusy = -1;
static gint ett_ansi_map_OCalledPartyBusyRes = -1;
static gint ett_ansi_map_ONoAnswer = -1;
static gint ett_ansi_map_ONoAnswerRes = -1;
static gint ett_ansi_map_PositionRequest = -1;
static gint ett_ansi_map_PositionRequestRes = -1;
static gint ett_ansi_map_PositionRequestForward = -1;
static gint ett_ansi_map_PositionRequestForwardRes = -1;
static gint ett_ansi_map_ACGDirective = -1;
static gint ett_ansi_map_RoamerDatabaseVerificationRequest = -1;
static gint ett_ansi_map_RoamerDatabaseVerificationRequestRes = -1;
static gint ett_ansi_map_AddService = -1;
static gint ett_ansi_map_AddServiceRes = -1;
static gint ett_ansi_map_DropService = -1;
static gint ett_ansi_map_DropServiceRes = -1;
static gint ett_ansi_map_OTASPRequest = -1;
static gint ett_ansi_map_OTASPRequestRes = -1;
static gint ett_ansi_map_AnnouncementList = -1;
static gint ett_ansi_map_CDMACodeChannelInformation = -1;
static gint ett_ansi_map_CDMACodeChannelList = -1;
static gint ett_ansi_map_CDMATargetMAHOInformation = -1;
static gint ett_ansi_map_CDMATargetMAHOList = -1;
static gint ett_ansi_map_CDMATargetMeasurementInformation = -1;
static gint ett_ansi_map_CDMATargetMeasurementList = -1;
static gint ett_ansi_map_IntersystemTermination = -1;
static gint ett_ansi_map_LocalTermination = -1;
static gint ett_ansi_map_Profile = -1;
static gint ett_ansi_map_PSTNTermination = -1;
static gint ett_ansi_map_TargetMeasurementInformation = -1;
static gint ett_ansi_map_TargetMeasurementList = -1;
static gint ett_ansi_map_TerminationList = -1;
static gint ett_ansi_map_TerminationList_item = -1;
static gint ett_ansi_map_CDMAServiceOptionList = -1;
static gint ett_ansi_map_PSID_RSIDList = -1;
static gint ett_ansi_map_TargetCellIDList = -1;
static gint ett_ansi_map_CDMAConnectionReferenceInformation = -1;
static gint ett_ansi_map_CDMAConnectionReferenceList = -1;
static gint ett_ansi_map_CDMAConnectionReferenceList_item = -1;
static gint ett_ansi_map_AnalogRedirectRecord = -1;
static gint ett_ansi_map_CDMAChannelNumberList = -1;
static gint ett_ansi_map_CDMAChannelNumberList_item = -1;
static gint ett_ansi_map_CDMARedirectRecord = -1;
static gint ett_ansi_map_MSID = -1;
static gint ett_ansi_map_DataAccessElement = -1;
static gint ett_ansi_map_DataAccessElementList = -1;
static gint ett_ansi_map_DataAccessElementList_item = -1;
static gint ett_ansi_map_DataUpdateResult = -1;
static gint ett_ansi_map_DataUpdateResultList = -1;
static gint ett_ansi_map_DestinationAddress = -1;
static gint ett_ansi_map_ExecuteScript = -1;
static gint ett_ansi_map_ModificationRequest = -1;
static gint ett_ansi_map_ModificationRequestList = -1;
static gint ett_ansi_map_ModificationResult = -1;
static gint ett_ansi_map_ModificationResultList = -1;
static gint ett_ansi_map_ServiceDataAccessElement = -1;
static gint ett_ansi_map_ServiceDataAccessElementList = -1;
static gint ett_ansi_map_ServiceDataResult = -1;
static gint ett_ansi_map_ServiceDataResultList = -1;
static gint ett_ansi_map_SRFCapability = -1;
static gint ett_ansi_map_TriggerAddressList = -1;
static gint ett_ansi_map_TriggerAddressList_item = -1;
static gint ett_ansi_map_TriggerList = -1;
static gint ett_ansi_map_WINCapability = -1;
static gint ett_ansi_map_WIN_Trigger = -1;
static gint ett_ansi_map_WIN_TriggerList = -1;
static gint ett_ansi_map_CallRecoveryID = -1;
static gint ett_ansi_map_CallRecoveryIDList = -1;
static gint ett_ansi_map_GapInterval = -1;
static gint ett_ansi_map_MobileStationMSID = -1;
static gint ett_ansi_map_NewlyAssignedMSID = -1;
static gint ett_ansi_map_InvokeData = -1;
static gint ett_ansi_map_ReturnData = -1;

/*--- End of included file: packet-ansi_map-ett.c ---*/
#line 346 "packet-ansi_map-template.c"

/* Global variables */
static dissector_handle_t data_handle=NULL;
static dissector_table_t is637_tele_id_dissector_table; /* IS-637 Teleservice ID */
static dissector_table_t is683_dissector_table; /* IS-683-A (OTA) */
static dissector_table_t is801_dissector_table; /* IS-801 (PLD) */
static packet_info *g_pinfo;
static proto_tree *g_tree;
tvbuff_t *SMS_BearerData_tvb = NULL;
static gboolean is683_ota;
static gboolean is801_pld;
static gboolean ansi_map_is_invoke;
static guint32 OperationCode;

/* Transaction table */
static GHashTable *TransactionId_table=NULL;

static void
TransactionId_table_cleanup(gpointer key , gpointer value, gpointer user_data _U_){

	guint8 *opcode = value;
	gchar *TransactionId_str = key;

	if ( TransactionId_str ){
		g_free(TransactionId_str);
	}
	if (opcode){
		g_free(opcode);
	}

}

void
ansi_map_init_transaction_table(void){

	/* Destroy any existing memory chunks / hashes. */
	if (TransactionId_table){
		g_hash_table_foreach(TransactionId_table, TransactionId_table_cleanup, NULL);
		g_hash_table_destroy(TransactionId_table);
	}

	TransactionId_table = g_hash_table_new(g_str_hash, g_str_equal);

}

static void
ansi_map_init_protocol(void)
{
	ansi_map_init_transaction_table();
} 
/* value strings */
const value_string ansi_map_opr_code_strings[] = {
    { 1,	"Handoff Measurement Request" },
    { 2,	"Facilities Directive" },
    { 3,	"Mobile On Channel" },
    { 4,	"Handoff Back" },
    { 5,	"Facilities Release" },
    { 6,	"Qualification Request" },
    { 7,	"Qualification Directive" },
    { 8,	"Blocking" },
    { 9,	"Unblocking" },
    { 10,	"Reset Circuit" },
    { 11,	"Trunk Test" },
    { 12,	"Trunk Test Disconnect" },
    { 13,	"Registration Notification" },
    { 14,	"Registration Cancellation" },
    { 15,	"Location Request" },
    { 16,	"Routing Request" },
    { 17,	"Feature Request" },
    { 18,	"Reserved 18 (Service Profile Request, IS-41-C)" },
    { 19,	"Reserved 19 (Service Profile Directive, IS-41-C)" },
    { 20,	"Unreliable Roamer Data Directive" },
    { 21,	"Reserved 21 (Call Data Request, IS-41-C)" },
    { 22,	"MS Inactive" },
    { 23,	"Transfer To Number Request" },
    { 24,	"Redirection Request" },
    { 25,	"Handoff To Third" },
    { 26,	"Flash Request" },
    { 27,	"Authentication Directive" },
    { 28,	"Authentication Request" },
    { 29,	"Base Station Challenge" },
    { 30,	"Authentication Failure Report" },
    { 31,	"Count Request" },
    { 32,	"Inter System Page" },
    { 33,	"Unsolicited Response" },
    { 34,	"Bulk Deregistration" },
    { 35,	"Handoff Measurement Request 2" },
    { 36,	"Facilities Directive 2" },
    { 37,	"Handoff Back 2" },
    { 38,	"Handoff To Third 2" },
    { 39,	"Authentication Directive Forward" },
    { 40,	"Authentication Status Report" },
    { 41,	"Reserved 41" },
    { 42,	"Information Directive" },
    { 43,	"Information Forward" },
    { 44,	"Inter System Answer" },
    { 45,	"Inter System Page 2" },
    { 46,	"Inter System Setup" },
    { 47,	"Origination Request" },
    { 48,	"Random Variable Request" },
    { 49,	"Redirection Directive" },
    { 50,	"Remote User Interaction Directive" },
    { 51,	"SMS Delivery Backward" },
    { 52,	"SMS Delivery Forward" },
    { 53,	"SMS Delivery Point to Point" },
    { 54,	"SMS Notification" },
    { 55,	"SMS Request" },
    { 56,	"OTASP Request" },
    { 57,	"Information Backward" },
    { 58,	"Change Facilities" },
    { 59,	"Change Service" },
    { 60,	"Parameter Request" },
    { 61,	"TMSI Directive" },
    { 62,	"Reserved 62" },
    { 63,	"Service Request" },
    { 64,	"Analyzed Information Request" },
    { 65,	"Connection Failure Report" },
    { 66,	"Connect Resource" },
    { 67,	"Disconnect Resource" },
    { 68,	"Facility Selected and Available" },
    { 69,	"Instruction Request" },
    { 70,	"Modify" },
    { 71,	"Reset Timer" },
    { 72,	"Search" },
    { 73,	"Seize Resource" },
    { 74,	"SRF Directive" },
    { 75,	"T Busy" },
    { 76,	"T NoAnswer" },
    { 77,	"Release" },
    { 78,	"SMS Delivery Point to Point Ack" },
    { 79,	"Message Directive" },
    { 80,	"Bulk Disconnection" },
    { 81,	"Call Control Directive" },
    { 82,	"O Answer" },
    { 83,	"O Disconnect" },
    { 84,	"Call Recovery Report" },
    { 85,	"T Answer" },
    { 86,	"T Disconnect" },
    { 87,	"Unreliable Call Data" },
    { 88,	"O CalledPartyBusy" },
    { 89,	"O NoAnswer" },
    { 90,	"Position Request" },
    { 91,	"Position Request Forward" },
    { 92,	"Call Termination Report" },
    { 93,	"Geo Position Directive" },
    { 94,	"Geo Position Request" },
    { 95,	"Inter System Position Request" },
    { 96,	"Inter System Position Request Forward" },
    { 97,	"ACG Directive" },
    { 98,	"Roamer Database Verification Request" },
    { 99,	"Add Service" },
    { 100,	"Drop Service" },
    { 0, NULL },
};

static int dissect_invokeData(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset);
static int dissect_returnData(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset);
static int dissect_ansi_map_SystemMyTypeCode(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_);

typedef struct dgt_set_t
{
    unsigned char out[15];
}
dgt_set_t;

static dgt_set_t Dgt_tbcd = {
    {
  /*  0   1   2   3   4   5   6   7   8   9   a   b   c   d   e */
     '0','1','2','3','4','5','6','7','8','9','?','B','C','*','#'
    }
};
static dgt_set_t Dgt1_9_bcd = {
    {
  /*  0   1   2   3   4   5   6   7   8   9   a   b   c   d   e */
     '0','1','2','3','4','5','6','7','8','9','?','?','?','?','?'
    }
};
/* Assumes the rest of the tvb contains the digits to be turned into a string 
 */
static char*
unpack_digits2(tvbuff_t *tvb, int offset,dgt_set_t *dgt){

	int length;
	guint8 octet;
	int i=0;
	char *digit_str;

	length = tvb_length(tvb);
	if (length < offset)
		return "";
	digit_str = ep_alloc((length - offset)*2+1);

	while ( offset < length ){

		octet = tvb_get_guint8(tvb,offset);
		digit_str[i] = dgt->out[octet & 0x0f]; 
		i++;

		/*
		 * unpack second value in byte
		 */
		octet = octet >> 4;

		if (octet == 0x0f)	/* odd number bytes - hit filler */
			break;

		digit_str[i] = dgt->out[octet & 0x0f]; 
		i++;
		offset++;

	}
	digit_str[i]= '\0';
	return digit_str;
}



/* Type of Digits (octet 1, bits A-H) */
static const value_string ansi_map_type_of_digits_vals[] = {
  {   0, "Not Used" },
  {   1, "Dialed Number or Called Party Number" },
  {   2, "Calling Party Number" },
  {   3, "Caller Interaction" },
  {   4, "Routing Number" },
  {   5, "Billing Number" },
  {   6, "Destination Number" },
  {   7, "LATA" },
  {   8, "Carrier" },
  { 0, NULL }
};
/* Nature of Number (octet 2, bits A-H )*/
static const true_false_string ansi_map_na_bool_val  = {
  "International",
  "National"
};
static const true_false_string ansi_map_pi_bool_val  = {
  "Presentation Restricted",
  "Presentation Allowed"
};
static const true_false_string ansi_map_navail_bool_val  = {
  "Number is not available",
  "Number is available"
};
static const true_false_string ansi_map_si_bool_val  = {
  "User provided, screening passed",
  "User provided, not screened"
};
static const value_string ansi_map_si_vals[]  = {
    {   0, "User provided, not screened"},
    {   1, "User provided, screening passed"},
    {   2, "User provided, screening failed"},
    {   3, "Network provided"},
	{ 0, NULL }
};
/* Encoding (octet 3, bits A-D) */
static const value_string ansi_map_digits_enc_vals[]  = {
    {   0, "Not used"},
    {   1, "BCD"},
    {   2, "IA5"},
    {   3, "Octet string"},
	{	0, NULL }
};
/* Numbering Plan (octet 3, bits E-H) */
static const value_string ansi_map_np_vals[]  = {
    {   0, "Unknown or not applicable"},
    {   1, "ISDN Numbering"},
    {   2, "Telephony Numbering (ITU-T Rec. E.164,E.163)"},
    {   3, "Data Numbering (ITU-T Rec. X.121)"},
    {   4, "Telex Numbering (ITU-T Rec. F.69)"},
    {   5, "Maritime Mobile Numbering"},
    {   6, "Land Mobile Numbering (ITU-T Rec. E.212)"},
    {   7, "Private Numbering Plan"},
    {   13, "SS7 Point Code (PC) and Subsystem Number (SSN)"},
    {   14, "Internet Protocol (IP) Address."},
    {   15, "Reserved for extension"},
	{	0, NULL }
};

static void 
dissect_ansi_map_min_type(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree){
	char		*digit_str;
	int offset = 0;
    proto_item *item;
    proto_tree *subtree;

	item = get_ber_last_created_item();
	subtree = proto_item_add_subtree(item, ett_mintype);
	
	digit_str = unpack_digits2(tvb, offset, &Dgt1_9_bcd);
	proto_tree_add_string(subtree, hf_ansi_map_bcd_digits, tvb, offset, -1, digit_str);
	proto_item_append_text(item, " - %s", digit_str);
}

static void 
dissect_ansi_map_digits_type(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree){
	
	guint8 octet;
	guint8 b1,b2,b3,b4;
	int offset = 0;
	char		*digit_str;
    proto_item *item;
    proto_tree *subtree;

	item = get_ber_last_created_item();
	subtree = proto_item_add_subtree(item, ett_digitstype);

	/* Octet 1 */
	proto_tree_add_item(subtree, hf_ansi_map_type_of_digits, tvb, offset, 1, FALSE);
	offset++;
	/* Octet 2 */
	proto_tree_add_item(subtree, hf_ansi_map_reservedBitHG, tvb, offset, 1, FALSE);
	proto_tree_add_item(subtree, hf_ansi_map_si, tvb, offset, 1, FALSE);
	proto_tree_add_item(subtree, hf_ansi_map_reservedBitD, tvb, offset, 1, FALSE);
	proto_tree_add_item(subtree, hf_ansi_map_navail, tvb, offset, 1, FALSE);
	proto_tree_add_item(subtree, hf_ansi_map_pi, tvb, offset, 1, FALSE);
	proto_tree_add_item(subtree, hf_ansi_map_na, tvb, offset, 1, FALSE);
	offset++;
	/* Octet 3 */
	octet = tvb_get_guint8(tvb,offset);
	proto_tree_add_item(subtree, hf_ansi_map_np, tvb, offset, 1, FALSE);
	proto_tree_add_item(subtree, hf_ansi_map_digits_enc, tvb, offset, 1, FALSE);
	offset++;
	/* Octet 4 - */
	switch(octet>>4){
	case 0:/* Unknown or not applicable */
		switch ((octet&0xf)){
		case 1:
			/* BCD Coding */
			digit_str = unpack_digits2(tvb, offset, &Dgt_tbcd);
			proto_tree_add_string(subtree, hf_ansi_map_bcd_digits, tvb, offset, -1, digit_str);
			proto_item_append_text(item, " - %s", digit_str);
			break;
		case 2:
			/* IA5 Coding */
			proto_tree_add_item(subtree, hf_ansi_map_ia5_digits, tvb, offset, -1, FALSE);
			proto_item_append_text(item, " - %s", tvb_get_string(tvb,offset,-1));
			break;
		case 3:
			/* Octet string */
			break;
		default:
			break;
		}
		break;
	case 1:/* ISDN Numbering (not used in this Standard). */
	case 3:/* Data Numbering (ITU-T Rec. X.121) (not used in this Standard). */
	case 4:/* Telex Numbering (ITU-T Rec. F.69) (not used in this Standard). */
	case 5:/* Maritime Mobile Numbering (not used in this Standard). */
		proto_tree_add_text(subtree, tvb, offset, -1, "This Number plan should not have been used");
		break;
	case 2:/* Telephony Numbering (ITU-T Rec. E.164,E.163). */
	case 6:/* Land Mobile Numbering (ITU-T Rec. E.212) */
	case 7:/* Private Numbering Plan */
		proto_tree_add_item(subtree, hf_ansi_map_nr_digits, tvb, offset, 1, FALSE);
		offset++;
		switch ((octet&0xf)){
		case 1:
			/* BCD Coding */
			digit_str = unpack_digits2(tvb, offset, &Dgt_tbcd);
			proto_tree_add_string(subtree, hf_ansi_map_bcd_digits, tvb, offset, -1, digit_str);
			proto_item_append_text(item, " - %s", digit_str);
			break;
		case 2:
			/* IA5 Coding */
			proto_tree_add_item(subtree, hf_ansi_map_ia5_digits, tvb, offset, -1, FALSE);
			proto_item_append_text(item, " - %s", tvb_get_string(tvb,offset,-1));
			break;
		case 3:
			/* Octet string */
			break;
		default:
			break;
		}
		break;
	case 13:/* ANSI SS7 Point Code (PC) and Subsystem Number (SSN). */
		switch ((octet&0xf)){
		case 3:
			/* Octet string */
			/* Point Code Member Number octet 2 */
			b1 = tvb_get_guint8(tvb,offset);
			offset++;
			/* Point Code Cluster Number octet 3 */
			b2 = tvb_get_guint8(tvb,offset);
			offset++;
			/* Point Code Network Number octet 4 */
			b3 = tvb_get_guint8(tvb,offset);
			offset++;
			/* Subsystem Number (SSN) octet 5 */
			b4 = tvb_get_guint8(tvb,offset);
			proto_tree_add_text(subtree, tvb, offset-3, 4 ,	"Point Code %u-%u-%u  SSN %u",
				b3, b2, b1, b4);
			proto_item_append_text(item, " - Point Code %u-%u-%u  SSN %u", b3, b2, b1, b4);
			break;
		default:
			break;
		}
		break;
	case 14:/* Internet Protocol (IP) Address. */
		break;
	default:
		proto_tree_add_text(subtree, tvb, offset, -1, "This Number plan should not have been used");
		break;
	}

}
/* 6.5.3.13. Subaddress */

static const true_false_string ansi_map_Odd_Even_Ind_bool_val  = {
  "Odd",
  "Even"
};
/* Type of Subaddress (octet 1, bits E-G) */
static const value_string ansi_map_sub_addr_type_vals[]  = {
    {   0, "NSAP (CCITT Rec. X.213 or ISO 8348 AD2)"},
    {   1, "User specified"},
    {   2, "Reserved"},
    {   3, "Reserved"},
    {   4, "Reserved"},
    {   5, "Reserved"},
    {   6, "Reserved"},
    {   7, "Reserved"},
	{	0, NULL }
};

static void 
dissect_ansi_map_subaddress(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree){
	int offset = 0;
    proto_item *item;
    proto_tree *subtree;

	item = get_ber_last_created_item();
	subtree = proto_item_add_subtree(item, ett_billingid);
	/* Type of Subaddress (octet 1, bits E-G) */
	proto_tree_add_item(subtree, hf_ansi_map_subaddr_type, tvb, offset, 1, FALSE);
	/* Odd/Even Indicator (O/E) (octet 1, bit D) */
	proto_tree_add_item(subtree, hf_ansi_map_subaddr_odd_even, tvb, offset, 1, FALSE);

}
/*
 * 6.5.2.2 ActionCode
 * Table 114 ActionCode value
 *
/* 6.5.2.2 ActionCode(TIA/EIA-41.5-D, page 5-129) */

static const value_string ansi_map_ActionCode_vals[]  = {
    {   0, "Not used"},
    {   1, "Continue processing"},
    {   2, "Disconnect call"},
    {   3, "Disconnect call leg"},
    {   4, "Conference Calling Drop Last Party"},
    {   5, "Bridge call leg(s) to conference call"},
    {   6, "Drop call leg on busy or routing failure"},
    {   7, "Disconnect all call legs"},
    {   8, "Attach MSC to OTAF"},
    {   9, "Initiate RegistrationNotification"},
    {   10, "Generate Public Encryption values"},
    {   11, "Generate A-key"},
    {   12, "Perform SSD Update procedure"},
    {   13, "Perform Re-authentication procedure"},
    {   14, "Release TRN"},
    {   15, "Commit A-key"},
    {   16, "Release Resources (e.g., A-key, Traffic Channel)"},
    {   17, "Record NEWMSID"},
    {   18, "Allocate Resources (e.g., Multiple message traffic channel delivery)."},
    {   19, "Generate Authentication Signature"},
    {   20, "Release leg and redirect subscriber"},
	{	0, NULL }
};
/* 6.5.2.3 AlertCode */

/* Pitch (octet 1, bits G-H) */
static const value_string ansi_map_AlertCode_Pitch_vals[]  = {
	{   0, "Medium pitch"},
	{   1, "High pitch"},
	{   2, "Low pitch"},
	{   3, "Reserved"},
	{	0, NULL }
};
/* Cadence (octet 1, bits A-F) */
static const value_string ansi_map_AlertCode_Cadence_vals[]  = {
	{   0, "NoTone"},
	{   1, "Long"},
	{   2, "ShortShort"},
	{   3, "ShortShortLong"},
	{   4, "ShortShort2"},
	{   5, "ShortLongShort"},
	{   6, "ShortShortShortShort"},
	{   7, "PBXLong"},
	{   8, "PBXShortShort"},
	{   9, "PBXShortShortLong"},
	{   0, "NoTone"},

	{   10, "PBXShortLongShort"},
	{   11, "PBXShortShortShortShort"},
	{   12, "PipPipPipPip"},
	{   13, "Reserved. Treat the same as value 0, NoTone"},
	{   14, "Reserved. Treat the same as value 0, NoTone"},
	{   15, "Reserved. Treat the same as value 0, NoTone"},
	{   16, "Reserved. Treat the same as value 0, NoTone"},
	{   17, "Reserved. Treat the same as value 0, NoTone"},
	{   18, "Reserved. Treat the same as value 0, NoTone"},
	{   19, "Reserved. Treat the same as value 0, NoTone"},
	{	20, NULL }
};

/* Alert Action (octet 2, bits A-C) */
static const value_string ansi_map_AlertCode_Alert_Action_vals[]  = {
	{   0, "Alert without waiting to report"},
	{   1, "Apply a reminder alert once"},
	{   2, "Other values reserved. Treat the same as value 0, Alert without waiting to report"},
	{   3, "Other values reserved. Treat the same as value 0, Alert without waiting to report"},
	{   4, "Other values reserved. Treat the same as value 0, Alert without waiting to report"},
	{   5, "Other values reserved. Treat the same as value 0, Alert without waiting to report"},
	{   6, "Other values reserved. Treat the same as value 0, Alert without waiting to report"},
	{   7, "Other values reserved. Treat the same as value 0, Alert without waiting to report"},
	{	0, NULL }
};
static void
dissect_ansi_map_alertcode(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree){

	int offset = 0;
    proto_item *item;
    proto_tree *subtree;

	item = get_ber_last_created_item();
	subtree = proto_item_add_subtree(item, ett_billingid);
	/* Pitch (octet 1, bits G-H) */
	proto_tree_add_item(subtree, hf_ansi_alertcode_pitch, tvb, offset, 1, FALSE);
	/* Cadence (octet 1, bits A-F) */
	proto_tree_add_item(subtree, hf_ansi_alertcode_cadence, tvb, offset, 1, FALSE);
	offset++;

	/* Alert Action (octet 2, bits A-C) */
	proto_tree_add_item(subtree, hf_ansi_alertcode_alertaction, tvb, offset, 1, FALSE);

}
/* 6.5.2.4 AlertResult */
/* Result (octet 1) */
static const value_string ansi_map_AlertResult_result_vals[]  = {
	{   0, "Not specified"},
	{   1, "Success"},
	{   2, "Failure"},
	{   3, "Denied"},
	{   4, "NotAttempted"},
	{   5, "NoPageResponse"},
	{   6, "Busy"},
	{	0, NULL }
};

/* 6.5.2.5 AnnouncementCode Updatef from NS0018Re*/
/* Tone (octet 1) */
static const value_string ansi_map_AnnouncementCode_tone_vals[]  = {
	{   0, "DialTone"},
	{   1, "RingBack or AudibleAlerting"},
	{   2, "InterceptTone or MobileReorder"},
	{   3, "CongestionTone or ReorderTone"},
	{   4, "BusyTone"},
	{   5, "ConfirmationTone"},
	{   6, "AnswerTone"},
	{   7, "CallWaitingTone"},
	{   8, "OffHookTone"},
	{   17, "RecallDialTone"},
	{   18, "BargeInTone"},
	{   20, "PPCInsufficientTone"},
	{   21, "PPCWarningTone1"},
	{   22, "PPCWarningTone2"},
	{   23, "PPCWarningTone3"},
	{   24, "PPCDisconnectTone"},
	{   25, "PPCRedirectTone"},
	{   63, "TonesOff"},
	{   192, "PipTone"},
	{   193, "AbbreviatedIntercept"},
	{   194, "AbbreviatedCongestion"},
	{   195, "WarningTone"},
	{   196, "DenialToneBurst"},
	{   197, "DialToneBurst"},
	{   250, "IncomingAdditionalCallTone"},
	{   251, "PriorityAdditionalCallTone"},
	{	0, NULL }
};
/* Class (octet 2, bits A-D) */
static const value_string ansi_map_AnnouncementCode_class_vals[]  = {
	{   0, "Concurrent"},
	{   1, "Sequential"},
	{	0, NULL }
};
/* Standard Announcement (octet 3) Updated with N.S0015 */
static const value_string ansi_map_AnnouncementCode_std_ann_vals[]  = {
	{   0, "None"},
	{   1, "UnauthorizedUser"},
	{   2, "InvalidESN"},
	{   3, "UnauthorizedMobile"},
	{   4, "SuspendedOrigination"},
	{   5, "OriginationDenied"},
	{   6, "ServiceAreaDenial"},
	{   16, "PartialDial"},
	{   17, "Require1Plus"},
	{   18, "Require1PlusNPA"},
	{   19, "Require0Plus"},
	{   20, "Require0PlusNPA"},
	{   21, "Deny1Plus"},
	{   22, "Unsupported10plus"},
	{   23, "Deny10plus"},
	{   24, "Unsupported10XXX"},
	{   25, "Deny10XXX"},
	{   26, "Deny10XXXLocally"},
	{   27, "Require10Plus"},
	{   28, "RequireNPA"},
	{   29, "DenyTollOrigination"},
	{   30, "DenyInternationalOrigination"},
	{   31, "Deny0Minus"},
	{   48, "DenyNumber"},
	{   49, "AlternateOperatorServices"},
	{   64, "No Circuit or AllCircuitsBusy or FacilityProblem"},
	{   65, "Overload"},
	{   66, "InternalOfficeFailure"},
	{   67, "NoWinkReceived"},
	{   68, "InterofficeLinkFailure"},
	{   69, "Vacant"},
	{   70, "InvalidPrefix or InvalidAccessCode"},
	{   71, "OtherDialingIrregularity"},
	{   80, "VacantNumber or DisconnectedNumber"},
	{   81, "DenyTermination"},
	{   82, "SuspendedTermination"},
	{   83, "ChangedNumber"},
	{   84, "InaccessibleSubscriber"},
	{   85, "DenyIncomingTol"},
	{   86, "RoamerAccessScreening"},
	{   87, "RefuseCall"},
	{   88, "RedirectCall"},
	{   89, "NoPageResponse"},
	{   90, "NoAnswer"},
	{   96, "RoamerIntercept"},
	{   97, "GeneralInformation"},
	{   112, "UnrecognizedFeatureCode"},
	{   113, "UnauthorizedFeatureCode"},
	{   114, "RestrictedFeatureCode"},
	{   115, "InvalidModifierDigits"},
	{   116, "SuccessfulFeatureRegistration"},
	{   117, "SuccessfulFeatureDeRegistration"},
	{   118, "SuccessfulFeatureActivation"},
	{   119, "SuccessfulFeatureDeActivation"},
	{   120, "InvalidForwardToNumber"},
	{   121, "CourtesyCallWarning"},
	{   128, "EnterPINSendPrompt"},
	{   129, "EnterPINPrompt"},
	{   130, "ReEnterPINSendPrompt"},
	{   131, "ReEnterPINPrompt"},
	{   132, "EnterOldPINSendPrompt"},
	{   133, "EnterOldPINPrompt"},
	{   134, "EnterNewPINSendPrompt"},
	{   135, "EnterNewPINPrompt"},
	{   136, "ReEnterNewPINSendPrompt"},
	{   137, "ReEnterNewPINPrompt"},
	{   138, "EnterPasswordPrompt"},
	{   139, "EnterDirectoryNumberPrompt"},
	{   140, "ReEnterDirectoryNumberPrompt"},
	{   141, "EnterFeatureCodePrompt"},
	{   142, "EnterEnterCreditCardNumberPrompt"},
	{   143, "EnterDestinationNumberPrompt"},
	{   152, "PPCInsufficientAccountBalance"},
	{   153, "PPCFiveMinuteWarning"},
	{   154, "PPCThreeMinuteWarning"},
	{   155, "PPCTwoMinuteWarning"},
	{   156, "PPCOneMinuteWarning"},
	{   157, "PPCDisconnect"},
	{   158, "PPCRedirect"},
	{	0, NULL }
};



static void
dissect_ansi_map_announcementcode(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree){

	int offset = 0;
    proto_item *item;
    proto_tree *subtree;

	item = get_ber_last_created_item();
	subtree = proto_item_add_subtree(item, ett_billingid);
	
	/* Tone (octet 1) */
	proto_tree_add_item(subtree, hf_ansi_map_announcementcode_tone, tvb, offset, 1, FALSE);
	offset++;
	/* Class (octet 2, bits A-D) */
	proto_tree_add_item(subtree, hf_ansi_map_announcementcode_class, tvb, offset, 1, FALSE);
	offset++;
	/* Standard Announcement (octet 3) */
	proto_tree_add_item(subtree, hf_ansi_map_announcementcode_std_ann, tvb, offset, 1, FALSE);
	offset++;
	/* Custom Announcement ( octet 4 )
		e.	The assignment of this octet is left to bilateral agreement. When a Custom
			Announcement is specified it takes precedence over either the Standard
			Announcement or Tone
	 */
	proto_tree_add_item(subtree, hf_ansi_map_announcementcode_cust_ann, tvb, offset, 1, FALSE);

}
/* 6.5.2.8 AuthenticationCapability Updated N.S0003*/
static const value_string ansi_map_AuthenticationCapability_vals[]  = {
	{   0, "Not used"},
	{   1, "No authentication required"},
	{   2, "Authentication required"},
	{   128, "Authentication required and UIM capable."},
	{	0, NULL }
};

/* 6.5.2.14 AuthorizationPeriod*/

/* Period (octet 1) */
static const value_string ansi_map_authorizationperiod_period_vals[]  = {
	{   0, "Not used"},
	{   1, "Per Call"},
	{   2, "Hours"},
	{   3, "Days"},
	{   4, "Weeks"},
	{   5, "Per Agreement"},
	{   6, "Indefinite (i.e., authorized until canceled or deregistered)"},
	{   7, "Number of calls. Re-authorization should be attempted after this number of (rejected) call attempts"},
	{	0, NULL }
};
/* Value (octet 2)
Number of minutes hours, days, weeks, or
number of calls (as per Period). If Period
indicates anything else the Value is set to zero
on sending and ignored on receipt. 
*/
static void
dissect_ansi_map_authorizationperiod(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree){

	int offset = 0;
    proto_item *item;
    proto_tree *subtree;

	item = get_ber_last_created_item();
	subtree = proto_item_add_subtree(item, ett_billingid);
	proto_tree_add_item(subtree, hf_ansi_map_authorizationperiod_period, tvb, offset, 1, FALSE);
	offset++;
	proto_tree_add_item(subtree, hf_ansi_map_value, tvb, offset, 1, FALSE);

}
/* 6.5.2.15 AvailabilityType */
static const value_string ansi_map_AvailabilityType_vals[]  = {
	{   0, "Not used"},
	{   1, "Unspecified MS inactivity type"},
	{	0, NULL }
};

/* 6.5.2.16 BillingID */
static void
dissect_ansi_map_billingid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree){

	int offset = 0;
    proto_item *item;
    proto_tree *subtree;

	item = get_ber_last_created_item();
	subtree = proto_item_add_subtree(item, ett_billingid);

	proto_tree_add_item(subtree, hf_ansi_map_MarketID, tvb, offset, 2, FALSE);
	offset = offset + 2;
	proto_tree_add_item(subtree, hf_ansi_map_swno, tvb, offset, 1, FALSE);
	offset++;
	/* ID Number */
	proto_tree_add_item(subtree, hf_ansi_map_idno, tvb, offset, 3, FALSE);
	offset = offset + 3;
	proto_tree_add_item(subtree, hf_ansi_map_segcount, tvb, offset, 1, FALSE);

}


/* 6.5.2.20 CallingFeaturesIndicator */
static const value_string ansi_map_FeatureActivity_vals[]  = {
	{   0, "Not used"},
	{   1, "Not authorized"},
	{   2, "Authorized but de-activated"},
	{   3, "Authorized and activated"},
	{	0, NULL }
};


static void
dissect_ansi_map_callingfeaturesindicator(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree){
	int offset = 0;
	int length; 
    proto_item *item;
    proto_tree *subtree;

	length = tvb_length_remaining(tvb,offset); 
	item = get_ber_last_created_item();
	subtree = proto_item_add_subtree(item, ett_mscid);

	/* Call Waiting: FeatureActivity, CW-FA (Octet 1 bits GH )		*/
	proto_tree_add_item(subtree, hf_ansi_map_callingfeaturesindicator_cwfa, tvb, offset, 1, FALSE);
	/* Call Forwarding No Answer FeatureActivity, CFNA-FA (Octet 1 bits EF )	*/
	proto_tree_add_item(subtree, hf_ansi_map_callingfeaturesindicator_cfnafa, tvb, offset, 1, FALSE);
	/* Call Forwarding Busy FeatureActivity, CFB-FA (Octet 1 bits CD )	*/
	proto_tree_add_item(subtree, hf_ansi_map_callingfeaturesindicator_cfbfa, tvb, offset, 1, FALSE);
	/* Call Forwarding Unconditional FeatureActivity, CFU-FA (Octet 1 bits AB )	*/
	proto_tree_add_item(subtree, hf_ansi_map_callingfeaturesindicator_cfufa, tvb, offset, 1, FALSE);
	offset++;
	length--;

	/* Call Transfer: FeatureActivity, CT-FA (Octet 2 bits GH )		*/
	proto_tree_add_item(subtree, hf_ansi_map_callingfeaturesindicator_ctfa, tvb, offset, 1, FALSE);
	/* Voice Privacy FeatureActivity, VP-FA (Octet 2 bits EF ) 	*/
	proto_tree_add_item(subtree, hf_ansi_map_callingfeaturesindicator_vpfa, tvb, offset, 1, FALSE);
	/* Call Delivery: FeatureActivity (not interpreted on reception by IS-41-C or later)
		CD-FA (Octet 2 bits CD ) 	*/
	proto_tree_add_item(subtree, hf_ansi_map_callingfeaturesindicator_cdfa, tvb, offset, 1, FALSE);
	/* Three-Way Calling FeatureActivity, 3WC-FA (Octet 2 bits AB )	*/
	proto_tree_add_item(subtree, hf_ansi_map_callingfeaturesindicator_3wcfa, tvb, offset, 1, FALSE);
	offset++;
	length--;


	/* Calling Number Identification Restriction Override FeatureActivity CNIROver-FA (Octet 3 bits GH )	*/
	proto_tree_add_item(subtree, hf_ansi_map_callingfeaturesindicator_cniroverfa, tvb, offset, 1, FALSE);
	/* Calling Number Identification Restriction: FeatureActivity CNIR-FA (Octet 3 bits EF )	*/
	proto_tree_add_item(subtree, hf_ansi_map_callingfeaturesindicator_cnirfa, tvb, offset, 1, FALSE);
	/* Calling Number Identification Presentation: FeatureActivity CNIP2-FA (Octet 3 bits CD )	*/
	proto_tree_add_item(subtree, hf_ansi_map_callingfeaturesindicator_cnip2fa, tvb, offset, 1, FALSE);
	/* Calling Number Identification Presentation: FeatureActivity CNIP1-FA (Octet 3 bits AB ) 	*/
	proto_tree_add_item(subtree, hf_ansi_map_callingfeaturesindicator_cnip1fa, tvb, offset, 1, FALSE);
	length--;
	if ( length == 0)
		return;
	offset++;

	/* USCF divert to voice mail: FeatureActivity USCFvm-FA (Octet 4 bits GH ) 	*/
	proto_tree_add_item(subtree, hf_ansi_map_callingfeaturesindicator_uscfvmfa, tvb, offset, 1, FALSE);
	/* Answer Hold: FeatureActivity AH-FA (Octet 4 bits EF ) N.S0029-0 v1.0	*/
	proto_tree_add_item(subtree, hf_ansi_map_callingfeaturesindicator_ahfa, tvb, offset, 1, FALSE);
	/* Data Privacy Feature Activity DP-FA (Octet 4 bits CD ) N.S0008-0 v 1.0	*/
	proto_tree_add_item(subtree, hf_ansi_map_callingfeaturesindicator_dpfa, tvb, offset, 1, FALSE);
	/* Priority Call Waiting FeatureActivity PCW-FA (Octet 4 bits AB )	*/
	proto_tree_add_item(subtree, hf_ansi_map_callingfeaturesindicator_pcwfa, tvb, offset, 1, FALSE);
	length--;
	if ( length == 0)
		return;
	offset++;

	/* USCF divert to mobile station provided DN:FeatureActivity.USCFms-FA (Octet 5 bits AB ) */
	proto_tree_add_item(subtree, hf_ansi_map_callingfeaturesindicator_uscfmsfa, tvb, offset, 1, FALSE);
	/* USCF divert to network registered DN:FeatureActivity. USCFnr-FA (Octet 5 bits CD )*/
	proto_tree_add_item(subtree, hf_ansi_map_callingfeaturesindicator_uscfnrfa, tvb, offset, 1, FALSE);
	/* CDMA-Packet Data Service: FeatureActivity. CPDS-FA (Octet 5 bits EF ) N.S0029-0 v1.0*/
	proto_tree_add_item(subtree, hf_ansi_map_callingfeaturesindicator_cpdsfa, tvb, offset, 1, FALSE);
	/* CDMA-Concurrent Service:FeatureActivity. CCS-FA (Octet 5 bits GH ) N.S0029-0 v1.0*/
	proto_tree_add_item(subtree, hf_ansi_map_callingfeaturesindicator_ccsfa, tvb, offset, 1, FALSE);
	length--;
	if ( length == 0)
		return;
	offset++;

	/* TDMA Enhanced Privacy and Encryption:FeatureActivity.TDMA EPE-FA (Octet 6 bits AB ) N.S0029-0 v1.0*/
	proto_tree_add_item(subtree, hf_ansi_map_callingfeaturesindicator_epefa, tvb, offset, 1, FALSE);
}


/* 6.5.2.27 CancellationType */
static const value_string ansi_map_CancellationType_vals[]  = {
	{   0, "Not used"},
	{   1, "ServingSystemOption"},
	{   2, "ReportInCall."},
	{   3, "Discontinue"},
	{	0, NULL }
};

/* 6.5.2.29 CDMACallMode Updated with N.S0029-0 v1.0*/
/* Call Mode (octet 1, bit A) */
static const true_false_string ansi_map_CDMACallMode_cdma_bool_val  = {
  "CDMA 800 MHz channel (Band Class 0) acceptable.",
  "CDMA 800 MHz channel (Band Class 0) not acceptable"
};
/* Call Mode (octet 1, bit B) */
static const true_false_string ansi_map_CallMode_amps_bool_val  = {
	"AAMPS 800 MHz channel acceptable",
	"AMPS 800 MHz channel not acceptable"
};
/* Call Mode (octet 1, bit C) */
static const true_false_string ansi_map_CallMode_namps_bool_val  = {
	"NAMPS 800 MHz channel acceptable",
	"NAMPS 800 MHz channel not acceptable"
};
/* Call Mode (octet 1, bit D) */
static const true_false_string ansi_map_CDMACallMode_cls1_bool_val  = {
  "CDMA 1900 MHz channel (Band Class 1) acceptable.",
  "CDMA 1900 MHz channel (Band Class 1) not acceptable"
};
/* Call Mode (octet 1, bit E) */
static const true_false_string ansi_map_CDMACallMode_cls2_bool_val  = {
  "TACS channel (Band Class 2) acceptable",
  "TACS channel (Band Class 2) not acceptable"
};
/* Call Mode (octet 1, bit F) */
static const true_false_string ansi_map_CDMACallMode_cls3_bool_val  = {
  "JTACS channel (Band Class 3) acceptable",
  "JTACS channel (Band Class 3) not acceptable"
};
/* Call Mode (octet 1, bit G) */
static const true_false_string ansi_map_CDMACallMode_cls4_bool_val  = {
  "Korean PCS channel (Band Class 4) acceptable",
  "Korean PCS channel (Band Class 4) not acceptable"
};
/* Call Mode (octet 1, bit H) */
static const true_false_string ansi_map_CDMACallMode_cls5_bool_val  = {
  "450 MHz channel (Band Class 5) not acceptable",
  "450 MHz channel (Band Class 5) not acceptable"
};
/* Call Mode (octet 2, bit A) */
static const true_false_string ansi_map_CDMACallMode_cls6_bool_val  = {
  "2 GHz channel (Band Class 6) acceptable.",
  "2 GHz channel (Band Class 6) not acceptable."
};

/* Call Mode (octet 2, bit B) */
static const true_false_string ansi_map_CDMACallMode_cls7_bool_val  = {
  "700 MHz channel (Band Class 7) acceptable",
  "700 MHz channel (Band Class 7) not acceptable"
};

/* Call Mode (octet 2, bit C) */
static const true_false_string ansi_map_CDMACallMode_cls8_bool_val  = {
  "1800 MHz channel (Band Class 8) acceptable",
  "1800 MHz channel (Band Class 8) not acceptable"
};
/* Call Mode (octet 2, bit D) */
static const true_false_string ansi_map_CDMACallMode_cls9_bool_val  = {
  "900 MHz channel (Band Class 9) acceptable",
  "900 MHz channel (Band Class 9) not acceptable"
};
/* Call Mode (octet 2, bit E) */
static const true_false_string ansi_map_CDMACallMode_cls10_bool_val  = {
  "Secondary 800 MHz channel (Band Class 10) acceptable.",
  "Secondary 800 MHz channel (Band Class 10) not acceptable."
};

static void
dissect_ansi_map_cdmacallmode(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree){
	int offset = 0;
	int length; 
    proto_item *item;
    proto_tree *subtree;

	length = tvb_length_remaining(tvb,offset); 

	item = get_ber_last_created_item();
	subtree = proto_item_add_subtree(item, ett_mscid);
	/* Call Mode (octet 1, bit H) */
	proto_tree_add_item(subtree, hf_ansi_map_cdmacallmode_cls5, tvb, offset, 1, FALSE);
	/* Call Mode (octet 1, bit G) */
	proto_tree_add_item(subtree, hf_ansi_map_cdmacallmode_cls4, tvb, offset, 1, FALSE);
	/* Call Mode (octet 1, bit F) */
	proto_tree_add_item(subtree, hf_ansi_map_cdmacallmode_cls3, tvb, offset, 1, FALSE);
	/* Call Mode (octet 1, bit E) */
	proto_tree_add_item(subtree, hf_ansi_map_cdmacallmode_cls2, tvb, offset, 1, FALSE);
	/* Call Mode (octet 1, bit D) */
	proto_tree_add_item(subtree, hf_ansi_map_cdmacallmode_cls1, tvb, offset, 1, FALSE);
	/* Call Mode (octet 1, bit C) */
	proto_tree_add_item(subtree, hf_ansi_map_cdmacallmode_namps, tvb, offset, 1, FALSE);
	/* Call Mode (octet 1, bit B) */
	proto_tree_add_item(subtree, hf_ansi_map_cdmacallmode_amps, tvb, offset, 1, FALSE);
	/* Call Mode (octet 1, bit A) */
	proto_tree_add_item(subtree, hf_ansi_map_cdmacallmode_cdma, tvb, offset, 1, FALSE);

	length--; 
	if ( length == 0)
		return;
	offset++;

	/* Call Mode (octet 2, bit E) */
	proto_tree_add_item(subtree, hf_ansi_map_cdmacallmode_cls10, tvb, offset, 1, FALSE);
	/* Call Mode (octet 2, bit D) */
	proto_tree_add_item(subtree, hf_ansi_map_cdmacallmode_cls9, tvb, offset, 1, FALSE);
	/* Call Mode (octet 2, bit C) */
	proto_tree_add_item(subtree, hf_ansi_map_cdmacallmode_cls8, tvb, offset, 1, FALSE);
	/* Call Mode (octet 2, bit B) */
	proto_tree_add_item(subtree, hf_ansi_map_cdmacallmode_cls7, tvb, offset, 1, FALSE);
	/* Call Mode (octet 2, bit A) */
	proto_tree_add_item(subtree, hf_ansi_map_cdmacallmode_cls6, tvb, offset, 1, FALSE);

}
/* 6.5.2.30 CDMAChannelData */
/* Updated with N.S0010-0 v 1.0 */

static const value_string ansi_map_cdmachanneldata_band_cls_vals[]  = {
	{   0, "800 MHz Cellular System"},
	{	0, NULL }
};

static void
dissect_ansi_map_cdmachanneldata(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree){

	int offset = 0;
	int length; 
    proto_item *item;
    proto_tree *subtree;

	length = tvb_length_remaining(tvb,offset);

	item = get_ber_last_created_item();
	subtree = proto_item_add_subtree(item, ett_cdmachanneldata);

	proto_tree_add_item(subtree, hf_ansi_map_reservedBitH, tvb, offset, 1, FALSE);
	proto_tree_add_item(subtree, hf_ansi_map_cdmachanneldata_Frame_Offset, tvb, offset, 1, FALSE);
	/* CDMA Channel Number */
	proto_tree_add_item(subtree, hf_ansi_map_cdmachanneldata_CDMA_ch_no, tvb, offset, 2, FALSE);
	offset = offset + 2;
	length = length -2;
	/* Band Class */
	proto_tree_add_item(subtree, hf_ansi_map_reservedBitH, tvb, offset, 1, FALSE);
	proto_tree_add_item(subtree, hf_ansi_map_cdmachanneldata_band_cls, tvb, offset, 1, FALSE);
	/* Long Code Mask */
	proto_tree_add_item(subtree, hf_ansi_map_cdmachanneldata_lc_mask_b6, tvb, offset, 1, FALSE);
	offset++;
	proto_tree_add_item(subtree, hf_ansi_map_cdmachanneldata_lc_mask_b5, tvb, offset, 1, FALSE);
	offset++;
	proto_tree_add_item(subtree, hf_ansi_map_cdmachanneldata_lc_mask_b4, tvb, offset, 1, FALSE);
	offset++;
	proto_tree_add_item(subtree, hf_ansi_map_cdmachanneldata_lc_mask_b3, tvb, offset, 1, FALSE);
	offset++;
	proto_tree_add_item(subtree, hf_ansi_map_cdmachanneldata_lc_mask_b2, tvb, offset, 1, FALSE);
	offset++;
	proto_tree_add_item(subtree, hf_ansi_map_cdmachanneldata_lc_mask_b1, tvb, offset, 1, FALSE);
	length = length - 6;
	if (length == 0)
		return;
	offset++;
	/* NP_EXT */
	proto_tree_add_item(subtree, hf_ansi_map_cdmachanneldata_np_ext, tvb, offset, 1, FALSE);
	/* Nominal Power */
	proto_tree_add_item(subtree, hf_ansi_map_cdmachanneldata_nominal_pwr, tvb, offset, 1, FALSE);
	/* Number Preamble */
	proto_tree_add_item(subtree, hf_ansi_map_cdmachanneldata_nr_preamble, tvb, offset, 1, FALSE);

}
/* 6.5.2.31 CDMACodeChannel */

/* 6.5.2.41 CDMAStationClassMark */
/* Power Class: (PC) (octet 1, bits A and B) */
static const value_string ansi_map_CDMAStationClassMark_pc_vals[]  = {
	{   0, "Class I"},
	{   1, "Class II"},
	{   2, "Class III"},
	{   3, "Reserved"},
	{	0, NULL }
};
/* Analog Transmission: (DTX) (octet 1, bit C) */
static const true_false_string ansi_map_CDMAStationClassMark_dtx_bool_val  = {
	"Discontinuous",
	"Continuous"
};
/* Slotted Mode Indicator: (SMI) (octet 1, bit F) */
static const true_false_string ansi_map_CDMAStationClassMark_smi_bool_val  = {
	"Slotted capable",
	"Slotted incapable"
};
/* Dual-mode Indicator(DMI) (octet 1, bit G) */
static const true_false_string ansi_map_CDMAStationClassMark_dmi_bool_val  = {
	"Dual-mode CDMA",
	"CDMA only"
};


static void
dissect_ansi_map_cdmastationclassmark(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree){
	int offset = 0;
    proto_item *item;
    proto_tree *subtree;

	item = get_ber_last_created_item();
	subtree = proto_item_add_subtree(item, ett_cdmastationclassmark);

	proto_tree_add_item(subtree, hf_ansi_map_reservedBitH, tvb, offset, 1, FALSE);
	/* Dual-mode Indicator(DMI) (octet 1, bit G) */
	proto_tree_add_item(subtree, hf_ansi_map_cdmastationclassmark_dmi, tvb, offset, 1, FALSE);
	/* Slotted Mode Indicator: (SMI) (octet 1, bit F) */
	proto_tree_add_item(subtree, hf_ansi_map_cdmastationclassmark_smi, tvb, offset, 1, FALSE);
	proto_tree_add_item(subtree, hf_ansi_map_reservedBitED, tvb, offset, 1, FALSE);
	/* Analog Transmission: (DTX) (octet 1, bit C) */
	proto_tree_add_item(subtree, hf_ansi_map_cdmastationclassmark_dtx, tvb, offset, 1, FALSE);
	/* Power Class: (PC) (octet 1, bits A and B) */
	proto_tree_add_item(subtree, hf_ansi_map_cdmastationclassmark_pc, tvb, offset, 1, FALSE);
}
/* 6.5.2.47 ChannelData */
/* Discontinuous Transmission Mode (DTX) (octet 1, bits E and D) */
static const value_string ansi_map_ChannelData_dtx_vals[]  = {
	{   0, "DTX disabled"},
	{   1, "Reserved. Treat the same as value 00, DTX disabled."},
	{   2, "DTX-low mode"},
	{   3, "DTX mode active or acceptable"},
	{	0, NULL }
};


static void
dissect_ansi_map_channeldata(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree){
	int offset = 0;
    proto_item *item;
    proto_tree *subtree;

	item = get_ber_last_created_item();
	subtree = proto_item_add_subtree(item, ett_channeldata);

	/* SAT Color Code (SCC) (octet 1, bits H and G) */
	proto_tree_add_item(subtree, hf_ansi_map_channeldata_scc, tvb, offset, 1, FALSE);
	/* Discontinuous Transmission Mode (DTX) (octet 1, bits E and D) */
	proto_tree_add_item(subtree, hf_ansi_map_channeldata_dtx, tvb, offset, 1, FALSE);
	/* Voice Mobile Attenuation Code (VMAC) (octet 1, bits A - C)*/
	proto_tree_add_item(subtree, hf_ansi_map_channeldata_vmac, tvb, offset, 1, FALSE);

	offset++;
	/* Channel Number (CHNO) ( octet 2 and 3 ) */
	proto_tree_add_item(subtree, hf_ansi_map_channeldata_chno, tvb, offset, 2, FALSE);

}

/* 6.5.2.50 ConfidentialityModes */
/* Updated with N.S0008-0 v 1.0*/
/* Voice Privacy (VP) Confidentiality Status (octet 1, bit A) */

static const true_false_string ansi_map_ConfidentialityModes_bool_val  = {
	"On",
	"Off"
};
static void
dissect_ansi_map_confidentialitymodes(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree){
	int offset = 0;
    proto_item *item;
    proto_tree *subtree;

	item = get_ber_last_created_item();
	subtree = proto_item_add_subtree(item, ett_confidentialitymodes);

	/* DataPrivacy (DP) Confidentiality Status (octet 1, bit C) */
	proto_tree_add_item(subtree, hf_ansi_map_ConfidentialityModes_dp, tvb, offset, 1, FALSE);
	/* Signaling Message Encryption (SE) Confidentiality Status (octet 1, bit B) */
	proto_tree_add_item(subtree, hf_ansi_map_ConfidentialityModes_se, tvb, offset, 1, FALSE);
	/* Voice Privacy (VP) Confidentiality Status (octet 1, bit A) */
	proto_tree_add_item(subtree, hf_ansi_map_ConfidentialityModes_vp, tvb, offset, 1, FALSE);

}

/* 6.5.2.51 ControlChannelData */

/* Digital Color Code (DCC) (octet 1, bit H and G) */
/* Control Mobile Attenuation Code (CMAC) (octet 1, bit A - C) */
/* Channel Number (CHNO) ( octet 2 and 3 ) */
/* Supplementary Digital Color Codes (SDCC1 and SDCC2) */
/* SDCC1 ( octet 4, bit D and C )*/
/* SDCC2 ( octet 4, bit A and B )*/



/* 6.5.2.52 CountUpdateReport */
static const value_string ansi_map_CountUpdateReport_vals[]  = {
	{   0, "Class I"},
	{   1, "Class II"},
	{   2, "Class III"},
	{   3, "Reserved"},
	{	0, NULL }
};

/* 6.5.2.53 DeniedAuthorizationPeriod */
/* Period (octet 1) */ 
static const value_string ansi_map_deniedauthorizationperiod_period_vals[]  = {
	{   0, "Not used"},
	{   1, "Per Call. Re-authorization should be attempted on the next call attempt"},
	{   2, "Hours"},
	{   3, "Days"},
	{   4, "Weeks"},
	{   5, "Per Agreement"},
	{   6, "Reserved"},
	{   7, "Number of calls. Re-authorization should be attempted after this number of (rejected) call attempts"},
	{   8, "Minutes"},
	{	0, NULL }
};
/* Value (octet 2)
Number of minutes hours, days, weeks, or
number of calls (as per Period). If Period
indicates anything else the Value is set to zero
on sending and ignored on receipt. 
*/

static void
dissect_ansi_map_deniedauthorizationperiod(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree){

	int offset = 0;
    proto_item *item;
    proto_tree *subtree;

	item = get_ber_last_created_item();
	subtree = proto_item_add_subtree(item, ett_billingid);
	proto_tree_add_item(subtree, hf_ansi_map_deniedauthorizationperiod_period, tvb, offset, 1, FALSE);
	offset++;
	proto_tree_add_item(subtree, hf_ansi_map_value, tvb, offset, 1, FALSE);

}


/* 6.5.2.57 DigitCollectionControl */
/* TODO Add decoding here */

/* 6.5.2.64 ExtendedMSCID */
static const value_string ansi_map_msc_type_vals[]  = {
	{   0, "Not specified"},
	{   1, "Serving MSC"},
	{   2, "Home MSC"},
	{   3, "Gateway MSC"},
	{   4, "HLR"},
	{   5, "VLR"},
	{   6, "EIR (reserved)"},
	{   7, "AC"},
	{   8, "Border MSC"},
	{   9, "Originating MSC"},
	{	0, NULL }
};

static void
dissect_ansi_map_extendedmscid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree){

	int offset = 0;
    proto_item *item;
    proto_tree *subtree;

	item = get_ber_last_created_item();
	subtree = proto_item_add_subtree(item, ett_extendedmscid);
	/* Type (octet 1) */
	proto_tree_add_item(subtree, hf_ansi_map_msc_type, tvb, offset, 1, FALSE);
	offset++;
	proto_tree_add_item(subtree, hf_ansi_map_MarketID, tvb, offset, 2, FALSE);
	offset = offset + 2;
	proto_tree_add_item(subtree, hf_ansi_map_swno, tvb, offset, 1, FALSE);

}
/* 6.5.2.65 ExtendedSystemMyTypeCode */
static void
dissect_ansi_map_extendedsystemmytypecode(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree){

	int offset = 0;
    proto_item *item;
    proto_tree *subtree;

	item = get_ber_last_created_item();
	subtree = proto_item_add_subtree(item, ett_extendedsystemmytypecode);
	/* Type (octet 1) */
	proto_tree_add_item(subtree, hf_ansi_map_msc_type, tvb, offset, 1, FALSE);
	offset++;
	offset = dissect_ansi_map_SystemMyTypeCode(TRUE, tvb, offset, pinfo, subtree, hf_ansi_map_systemMyTypeCode);
}


/* 6.5.2.68 GeographicAuthorization */
/* Geographic Authorization (octet 1) */
static const value_string ansi_map_GeographicAuthorization_vals[]  = {
	{   0, "Not used"},
	{   1, "Authorized for all MarketIDs served by the VLR"},
	{   2, "Authorized for this MarketID only"},
	{   3, "Authorized for this MarketID and Switch Number only"},
	{   4, "Authorized for this LocationAreaID within a MarketID only"},
	{   5, "VLR"},
	{   6, "EIR (reserved)"},
	{   7, "AC"},
	{   8, "Border MSC"},
	{   9, "Originating MSC"},
	{	0, NULL }
};

/* 6.5.2.71 HandoffState */
/* Party Involved (PI) (octet 1, bit A) */
static const true_false_string ansi_map_HandoffState_pi_bool_val  = {
	"Terminator is handing off",
	"Originator is handing off"
};
static void
dissect_ansi_map_handoffstate(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree){

	int offset = 0;
    proto_item *item;
    proto_tree *subtree;

	item = get_ber_last_created_item();
	subtree = proto_item_add_subtree(item, ett_handoffstate);
	/* Party Involved (PI) (octet 1, bit A) */
	proto_tree_add_item(subtree, hf_ansi_map_handoffstate_pi, tvb, offset, 1, FALSE);
}

/* 6.5.2.72 InterMSCCircuitID */
/* Trunk Member Number (M) Octet2 */
static void
dissect_ansi_map_intermsccircuitid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree){

	int offset = 0;
    proto_item *item;
    proto_tree *subtree;
	guint8 octet, octet2;

	item = get_ber_last_created_item();
	subtree = proto_item_add_subtree(item, ett_billingid);
	/* Trunk Group Number (G) Octet 1 */
	octet = tvb_get_guint8(tvb,offset);
	proto_tree_add_item(subtree, hf_ansi_map_tgn, tvb, offset, 1, FALSE);
	offset++;
	/* Trunk Member Number (M) Octet2 */
	octet2 = tvb_get_guint8(tvb,offset);
	proto_tree_add_item(subtree, hf_ansi_map_tmn, tvb, offset, 1, FALSE);
	proto_item_append_text(item, " (G %u/M %u)", octet, octet2);
}

/* 6.5.2.78 MessageWaitingNotificationCount */
/* Type of messages (octet 1) */
static const value_string ansi_map_MessageWaitingNotificationCount_type_vals[]  = {
	{   0, "Voice messages"},
	{   1, "Short Message Services (SMS) messages"},
	{   2, "Group 3 (G3) Fax messages"},
	{	0, NULL }
};

static void
dissect_ansi_map_messagewaitingnotificationcount(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree){

	int offset = 0;
    proto_item *item;
    proto_tree *subtree;

	item = get_ber_last_created_item();
	subtree = proto_item_add_subtree(item, ett_billingid);
	/* Type of messages (octet 1) */
	proto_tree_add_item(subtree, hf_ansi_map_messagewaitingnotificationcount_tom, tvb, offset, 1, FALSE);
	offset++;
	/* Number of Messages Waiting (octet 2) */
	proto_tree_add_item(subtree, hf_ansi_map_messagewaitingnotificationcount_no_mw, tvb, offset, 1, FALSE);

}

/* 6.5.2.79 MessageWaitingNotificationType */
/* Pip Tone (PT) (octet 1, bit A) */
static const true_false_string ansi_map_MessageWaitingNotificationType_pt_bool_val  = {
	"Pip Tone (PT) notification is required",
	"Pip Tone (PT) notification is not authorized or no notification is required"
};
/* Alert Pip Tone (APT) (octet 1, bit B) */
static const true_false_string ansi_map_MessageWaitingNotificationType_apt_bool_val  = {
	"Alert Pip Tone (APT) notification is required",
	"Alert Pip Tone (APT) notification is not authorized or notification is not required"
};
/* Message Waiting Indication (MWI) (octet 1, bits C and D) */
static const value_string ansi_map_MessageWaitingNotificationType_mwi_vals[]  = {
	{   0, "No MWI. Message Waiting Indication (MWI) notification is not authorized or notification is not required"},
	{   1, "Reserved"},
	{   2, "MWI On. Message Waiting Indication (MWI) notification is required. Messages waiting"},
	{   3, "MWI Off. Message Waiting Indication (MWI) notification is required. No messages waiting"},
	{	0, NULL }
};

static void
dissect_ansi_map_messagewaitingnotificationtype(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree){

	int offset = 0;
    proto_item *item;
    proto_tree *subtree;

	item = get_ber_last_created_item();
	subtree = proto_item_add_subtree(item, ett_billingid);
	
	/* Message Waiting Indication (MWI) (octet 1, bits C and D) */
	proto_tree_add_item(subtree, hf_ansi_map_messagewaitingnotificationtype_mwi, tvb, offset, 1, FALSE);
	/* Alert Pip Tone (APT) (octet 1, bit B) */
	proto_tree_add_item(subtree, hf_ansi_map_messagewaitingnotificationtype_apt, tvb, offset, 1, FALSE);
	/* Pip Tone (PT) (octet 1, bit A) */
	proto_tree_add_item(subtree, hf_ansi_map_messagewaitingnotificationtype_pt, tvb, offset, 1, FALSE);
}

/* 6.5.2.81 MobileIdentificationNumber */

/* 6.5.2.82 MSCID */

static void
dissect_ansi_map_mscid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree){
	int offset = 0;
    proto_item *item;
    proto_tree *subtree;

	item = get_ber_last_created_item();
	subtree = proto_item_add_subtree(item, ett_mscid);

	proto_tree_add_item(subtree, hf_ansi_map_MarketID, tvb, offset, 2, FALSE);
	offset = offset + 2;
	proto_tree_add_item(subtree, hf_ansi_map_swno, tvb, offset, 1, FALSE);
}


/* 6.5.2.84 MSLocation */
static void
dissect_ansi_map_mslocation(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree){
	int offset = 0;
    proto_item *item;
    proto_tree *subtree;

	item = get_ber_last_created_item();
	subtree = proto_item_add_subtree(item, ett_mscid);

	/* Latitude in tenths of a second octet 1 - 3 */
	proto_tree_add_item(subtree, hf_ansi_map_mslocation_lat, tvb, offset, 3, FALSE);
	offset = offset + 3;
	/* Longitude in tenths of a second octet 4 - 6 */
	proto_tree_add_item(subtree, hf_ansi_map_mslocation_long, tvb, offset, 3, FALSE);
	offset = offset + 3;
	/* Resolution in units of 1 foot octet 7, octet 8 optional */
	proto_tree_add_item(subtree, hf_ansi_map_mslocation_res, tvb, offset, -1, FALSE);

}
/* 6.5.2.85 NAMPSCallMode */
static void
dissect_ansi_map_nampscallmode(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree){
	int offset = 0;
    proto_item *item;
    proto_tree *subtree;

	item = get_ber_last_created_item();
	subtree = proto_item_add_subtree(item, ett_mscid);

	/* Call Mode (octet 1, bits A and B) */
	proto_tree_add_item(subtree, hf_ansi_map_nampscallmode_amps, tvb, offset, 1, FALSE);
	proto_tree_add_item(subtree, hf_ansi_map_nampscallmode_namps, tvb, offset, 1, FALSE);
}

/* 6.5.2.86 NAMPSChannelData */
/* Narrow Analog Voice Channel Assignment (NAVCA) (octet 1, bits A and B) */
static const value_string ansi_map_NAMPSChannelData_navca_vals[]  = {
	{   0, "Wide. 30 kHz AMPS voice channel"},
	{   1, "Upper. 10 kHz NAMPS voice channel"},
	{   2, "Middle. 10 kHz NAMPS voice channel"},
	{   3, "Lower. 10 kHz NAMPS voice channel"},
	{	0, NULL }
};
/* Color Code Indicator (CCIndicator) (octet 1, bits C, D, and E) */
static const value_string ansi_map_NAMPSChannelData_ccinidicator_vals[]  = {
	{   0, "ChannelData parameter SCC field applies"},
	{   1, "Digital SAT Color Code 1 (ignore SCC field)"},
	{   2, "Digital SAT Color Code 2 (ignore SCC field)"},
	{   3, "Digital SAT Color Code 3 (ignore SCC field)"},
	{   4, "Digital SAT Color Code 4 (ignore SCC field)"},
	{   5, "Digital SAT Color Code 5 (ignore SCC field)"},
	{   6, "Digital SAT Color Code 6 (ignore SCC field)"},
	{   7, "Digital SAT Color Code 7 (ignore SCC field)"},
	{	0, NULL }
};



static void
dissect_ansi_map_nampschanneldata(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree){
	int offset = 0;
    proto_item *item;
    proto_tree *subtree;

	item = get_ber_last_created_item();
	subtree = proto_item_add_subtree(item, ett_mscid);

	/* Color Code Indicator (CCIndicator) (octet 1, bits C, D, and E) */
	proto_tree_add_item(subtree, hf_ansi_map_nampschanneldata_CCIndicator, tvb, offset, 1, FALSE);
	/* Narrow Analog Voice Channel Assignment (NAVCA) (octet 1, bits A and B) */
	proto_tree_add_item(subtree, hf_ansi_map_nampschanneldata_navca, tvb, offset, 1, FALSE);

}

/* 6.5.2.88 OneTimeFeatureIndicator */
/* updated with N.S0012 */
/* Call Waiting for Future Incoming Call (CWFI) (octet 1, bits A and B) */
/* Call Waiting for Incoming Call (CWIC) (octet 1, bits C and D) */

static const value_string ansi_map_onetimefeatureindicator_cw_vals[]  = {
	{   0, "Ignore"},
	{   1, "No CW"},
	{   2, "Normal CW"},
	{   3, "Priority CW"},
	{	0, NULL }
};
/* MessageWaitingNotification (MWN) (octet 1, bits E and F) */
static const value_string ansi_map_onetimefeatureindicator_mwn_vals[]  = {
	{   0, "Ignore"},
	{   1, "Pip Tone Inactive"},
	{   2, "Pip Tone Active"},
	{   3, "Reserved"},
	{	0, NULL }
};
/* Calling Number Identification Restriction (CNIR) (octet 1, bits G and H)*/
static const value_string ansi_map_onetimefeatureindicator_cnir_vals[]  = {
	{   0, "Ignore"},
	{   1, "CNIR Inactive"},
	{   2, "CNIR Active"},
	{   3, "Reserved"},
	{	0, NULL }
};

/* Priority Access and Channel Assignment (PACA) (octet 2, bits A and B)*/
static const value_string ansi_map_onetimefeatureindicator_paca_vals[]  = {
	{   0, "Ignore"},
	{   1, "PACA Demand Inactive"},
	{   2, "PACA Demand Activated"},
	{   3, "Reserved"},
	{	0, NULL }
};

/* Flash Privileges (Flash) (octet 2, bits C and D) */
static const value_string ansi_map_onetimefeatureindicator_flash_vals[]  = {
	{   0, "Ignore"},
	{   1, "Flash Inactive"},
	{   2, "Flash Active"},
	{   3, "Reserved"},
	{	0, NULL }
};
/* Calling Name Restriction (CNAR) (octet 2, bits E and F) */
static const value_string ansi_map_onetimefeatureindicator_cnar_vals[]  = {
	{   0, "Ignore"},
	{   1, "Presentation Allowed"},
	{   2, "Presentation Restricted."},
	{   3, "Blocking Toggle"},
	{	0, NULL }
};
static void
dissect_ansi_map_onetimefeatureindicator(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree){
	int offset = 0;
    proto_item *item;
    proto_tree *subtree;

	item = get_ber_last_created_item();
	subtree = proto_item_add_subtree(item, ett_mscid);

	/* Calling Number Identification Restriction (CNIR) (octet 1, bits G and H)*/
	/* MessageWaitingNotification (MWN) (octet 1, bits E and F) */
	/* Call Waiting for Incoming Call (CWIC) (octet 1, bits C and D) */
	/* Call Waiting for Future Incoming Call (CWFI) (octet 1, bits A and B) */
	offset++;
	/* Calling Name Restriction (CNAR) (octet 2, bits E and F) */
	/* Flash Privileges (Flash) (octet 2, bits C and D) */
	/* Priority Access and Channel Assignment (PACA) (octet 2, bits A and B)*/


}

/* 6.5.2.90 OriginationTriggers */
/* All Origination (All) (octet 1, bit A) */
static const true_false_string ansi_map_originationtriggers_all_bool_val  = {
  "Launch an OriginationRequest for any call attempt. This overrides all other values",
  "Trigger is not active"
};

/* Local (octet 1, bit B) */
static const true_false_string ansi_map_originationtriggers_local_bool_val  = {
  "Launch an OriginationRequest for any local call attempt",
  "Trigger is not active"
};

/* Intra-LATA Toll (ILATA) (octet 1, bit C) */
static const true_false_string ansi_map_originationtriggers_ilata_bool_val  = {
  "Launch an OriginationRequest for any intra-LATA call attempt",
  "Trigger is not active"
};
/* Inter-LATA Toll (OLATA) (octet 1, bit D) */
static const true_false_string ansi_map_originationtriggers_olata_bool_val  = {
  "Launch an OriginationRequest for any inter-LATA toll call attempt",
  "Trigger is not active"
};
/* International (Int'l ) (octet 1, bit E) */
static const true_false_string ansi_map_originationtriggers_int_bool_val  = {
  "Launch an OriginationRequest for any international call attempt",
  "Trigger is not active"
};
/* World Zone (WZ) (octet 1, bit F) */
static const true_false_string ansi_map_originationtriggers_wz_bool_val  = {
  "Launch an OriginationRequest for any call attempt outside of the current World Zone (as defined in ITU-T Rec. E.164)",
  "Trigger is not active"
};

/* Unrecognized Number (Unrec) (octet 1, bit G) */
static const true_false_string ansi_map_originationtriggers_unrec_bool_val  = {
  "Launch an OriginationRequest for any call attempt to an unrecognized number",
  "Trigger is not active"
};
/* Revertive Call (RvtC) (octet 1, bit H)*/
static const true_false_string ansi_map_originationtriggers_rvtc_bool_val  = {
  "Launch an OriginationRequest for any Revertive Call attempt",
  "Trigger is not active"
};

/* Star (octet 2, bit A) */
static const true_false_string ansi_map_originationtriggers_star_bool_val  = {
  "Launch an OriginationRequest for any number beginning with a Star '*' digit",
  "Trigger is not active"
};

/* Double Star (DS) (octet 2, bit B) */
static const true_false_string ansi_map_originationtriggers_ds_bool_val  = {
  "Launch an OriginationRequest for any number beginning with two Star '**' digits",
  "Trigger is not active"
};
/* Pound (octet 2, bit C) */
static const true_false_string ansi_map_originationtriggers_pound_bool_val  = {
  "Launch an OriginationRequest for any number beginning with a Pound '#' digit",
  "Trigger is not active"
};
/* Double Pound (DP) (octet 2, bit D) */
static const true_false_string ansi_map_originationtriggers_dp_bool_val  = {
  "Launch an OriginationRequest for any number beginning with two Pound '##' digits",
  "Trigger is not active"
};
/* Prior Agreement (PA) (octet 2, bit E) */
static const true_false_string ansi_map_originationtriggers_pa_bool_val  = {
  "Launch an OriginationRequest for any number matching a criteria of a prior agreement",
  "Trigger is not active"
};

/* No digits (octet 3, bit A) */
static const true_false_string ansi_map_originationtriggers_nodig_bool_val  = {
  "Launch an OriginationRequest for any call attempt with no digits",
  "Trigger is not active"
};

/* 1 digit (octet 3, bit B) */
static const true_false_string ansi_map_originationtriggers_onedig_bool_val  = {
  "Launch an OriginationRequest for any call attempt with 1 digit",
  "Trigger is not active"
};
/* 1 digit (octet 3, bit C) */
static const true_false_string ansi_map_originationtriggers_twodig_bool_val  = {
  "Launch an OriginationRequest for any call attempt with 2 digits",
  "Trigger is not active"
};
/* 1 digit (octet 3, bit D) */
static const true_false_string ansi_map_originationtriggers_threedig_bool_val  = {
  "Launch an OriginationRequest for any call attempt with 3 digits",
  "Trigger is not active"
};
/* 1 digit (octet 3, bit E) */
static const true_false_string ansi_map_originationtriggers_fourdig_bool_val  = {
  "Launch an OriginationRequest for any call attempt with 4 digits",
  "Trigger is not active"
};
/* 1 digit (octet 3, bit F) */
static const true_false_string ansi_map_originationtriggers_fivedig_bool_val  = {
  "Launch an OriginationRequest for any call attempt with 5 digits",
  "Trigger is not active"
};
/* 1 digit (octet 3, bit G) */
static const true_false_string ansi_map_originationtriggers_sixdig_bool_val  = {
  "Launch an OriginationRequest for any call attempt with 6 digits",
  "Trigger is not active"
};
/* 1 digit (octet 3, bit H) */
static const true_false_string ansi_map_originationtriggers_sevendig_bool_val  = {
  "Launch an OriginationRequest for any call attempt with 7 digits",
  "Trigger is not active"
};
/* 1 digit (octet 4, bit A) */
static const true_false_string ansi_map_originationtriggers_eightdig_bool_val  = {
  "Launch an OriginationRequest for any call attempt with 8 digits",
  "Trigger is not active"
};
/* 1 digit (octet 4, bit B) */
static const true_false_string ansi_map_originationtriggers_ninedig_bool_val  = {
  "Launch an OriginationRequest for any call attempt with 9 digits",
  "Trigger is not active"
};
/* 1 digit (octet 4, bit C) */
static const true_false_string ansi_map_originationtriggers_tendig_bool_val  = {
  "Launch an OriginationRequest for any call attempt with 10 digits",
  "Trigger is not active"
};
/* 1 digit (octet 4, bit D) */
static const true_false_string ansi_map_originationtriggers_elevendig_bool_val  = {
  "Launch an OriginationRequest for any call attempt with 11 digits",
  "Trigger is not active"
};
/* 1 digit (octet 4, bit E) */
static const true_false_string ansi_map_originationtriggers_thwelvdig_bool_val  = {
  "Launch an OriginationRequest for any call attempt with 12 digits",
  "Trigger is not active"
};
/* 1 digit (octet 4, bit F) */
static const true_false_string ansi_map_originationtriggers_thirteendig_bool_val  = {
  "Launch an OriginationRequest for any call attempt with 13 digits",
  "Trigger is not active"
};
/* 1 digit (octet 4, bit G) */
static const true_false_string ansi_map_originationtriggers_fourteendig_bool_val  = {
  "Launch an OriginationRequest for any call attempt with 14 digits",
  "Trigger is not active"
};
/* 1 digit (octet 4, bit H) */
static const true_false_string ansi_map_originationtriggers_fifteendig_bool_val  = {
  "Launch an OriginationRequest for any call attempt with 15 digits",
  "Trigger is not active"
};

static void
dissect_ansi_map_originationtriggers(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree){

	int offset = 0;
    proto_item *item;
    proto_tree *subtree;

	item = get_ber_last_created_item();
	subtree = proto_item_add_subtree(item, ett_originationtriggers);

	/* Revertive Call (RvtC) (octet 1, bit H)*/
	proto_tree_add_item(subtree, hf_ansi_map_originationtriggers_rvtc, tvb, offset,	1, FALSE);
	/* Unrecognized Number (Unrec) (octet 1, bit G) */
	proto_tree_add_item(subtree, hf_ansi_map_originationtriggers_unrec, tvb, offset,	1, FALSE);
	/* World Zone (WZ) (octet 1, bit F) */
	proto_tree_add_item(subtree, hf_ansi_map_originationtriggers_wz, tvb, offset,	1, FALSE);
	/* International (Int'l ) (octet 1, bit E) */
	proto_tree_add_item(subtree, hf_ansi_map_originationtriggers_int, tvb, offset,	1, FALSE);
	/* Inter-LATA Toll (OLATA) (octet 1, bit D) */
	proto_tree_add_item(subtree, hf_ansi_map_originationtriggers_olata, tvb, offset,	1, FALSE);
	/* Intra-LATA Toll (ILATA) (octet 1, bit C) */
	proto_tree_add_item(subtree, hf_ansi_map_originationtriggers_ilata, tvb, offset,	1, FALSE);
	/* Local (octet 1, bit B) */
	proto_tree_add_item(subtree, hf_ansi_map_originationtriggers_local, tvb, offset,	1, FALSE);
	/* All Origination (All) (octet 1, bit A) */
	proto_tree_add_item(subtree, hf_ansi_map_originationtriggers_all, tvb, offset,	1, FALSE);
	offset++;

	/*Prior Agreement (PA) (octet 2, bit E) */
	proto_tree_add_item(subtree, hf_ansi_map_originationtriggers_pa, tvb, offset,	1, FALSE);
	/* Double Pound (DP) (octet 2, bit D) */
	proto_tree_add_item(subtree, hf_ansi_map_originationtriggers_dp, tvb, offset,	1, FALSE);
	/* Pound (octet 2, bit C) */
	proto_tree_add_item(subtree, hf_ansi_map_originationtriggers_pound, tvb, offset,	1, FALSE);
	/* Double Star (DS) (octet 2, bit B) */
	proto_tree_add_item(subtree, hf_ansi_map_originationtriggers_ds, tvb, offset,	1, FALSE);
	/* Star (octet 2, bit A) */
	proto_tree_add_item(subtree, hf_ansi_map_originationtriggers_star, tvb, offset,	1, FALSE);
	offset++;

	/* 7 digit (octet 3, bit H) */
	proto_tree_add_item(subtree, hf_ansi_map_originationtriggers_sevendig, tvb, offset,	1, FALSE);
	/* 6 digit (octet 3, bit G) */
	proto_tree_add_item(subtree, hf_ansi_map_originationtriggers_sixdig, tvb, offset,	1, FALSE);
	/* 5 digit (octet 3, bit F) */
	proto_tree_add_item(subtree, hf_ansi_map_originationtriggers_fivedig, tvb, offset,	1, FALSE);
	/* 4 digit (octet 3, bit E) */
	proto_tree_add_item(subtree, hf_ansi_map_originationtriggers_fourdig, tvb, offset,	1, FALSE);
	/* 3 digit (octet 3, bit D) */
	proto_tree_add_item(subtree, hf_ansi_map_originationtriggers_threedig, tvb, offset,	1, FALSE);
	/* 2 digit (octet 3, bit C) */
	proto_tree_add_item(subtree, hf_ansi_map_originationtriggers_twodig, tvb, offset,	1, FALSE);
	/* 1 digit (octet 3, bit B) */
	proto_tree_add_item(subtree, hf_ansi_map_originationtriggers_onedig, tvb, offset,	1, FALSE);
	/* No digits (octet 3, bit A) */
	proto_tree_add_item(subtree, hf_ansi_map_originationtriggers_nodig, tvb, offset,	1, FALSE);
	offset++;

	/* 15 digit (octet 4, bit H) */
	proto_tree_add_item(subtree, hf_ansi_map_originationtriggers_fifteendig, tvb, offset,	1, FALSE);
	/* 14 digit (octet 4, bit G) */
	proto_tree_add_item(subtree, hf_ansi_map_originationtriggers_fourteendig, tvb, offset,	1, FALSE);
	/* 13 digit (octet 4, bit F) */
	proto_tree_add_item(subtree, hf_ansi_map_originationtriggers_thirteendig, tvb, offset,	1, FALSE);
	/* 12 digit (octet 4, bit E) */
	proto_tree_add_item(subtree, hf_ansi_map_originationtriggers_thwelvedig, tvb, offset,	1, FALSE);
	/* 11 digit (octet 4, bit D) */
	proto_tree_add_item(subtree, hf_ansi_map_originationtriggers_elevendig, tvb, offset,	1, FALSE);
	/* 10 digit (octet 4, bit C) */
	proto_tree_add_item(subtree, hf_ansi_map_originationtriggers_tendig, tvb, offset,	1, FALSE);
	/* 9 digit (octet 4, bit B) */
	proto_tree_add_item(subtree, hf_ansi_map_originationtriggers_ninedig, tvb, offset,	1, FALSE);
	/* 8 digits (octet 4, bit A) */
	proto_tree_add_item(subtree, hf_ansi_map_originationtriggers_eightdig, tvb, offset,	1, FALSE);

}

/* 6.5.2.91 PACAIndicator */

/* Permanent Activation (PA) (octet 1, bit A) */
static const true_false_string ansi_map_pacaindicator_pa_bool_val  = {
  "PACA is permanently activated",
  "PACA is not permanently activated"
};

static const value_string ansi_map_PACA_Level_vals[]  = {
    {   0, "Not used"},
    {   1, "Priority Level. 1 This is the highest level"},
    {   2, "Priority Level 2"},
    {   3, "Priority Level 3"},
    {   4, "Priority Level 4"},
    {   5, "Priority Level 5"},
    {   6, "Priority Level 6"},
    {   7, "Priority Level 7"},
    {   8, "Priority Level 8"},
    {   8, "Priority Level 9"},
    {   10, "Priority Level 10"},
    {   11, "Priority Level 11"},
    {   12, "Priority Level 12"},
    {   13, "Priority Level 13"},
    {   14, "Priority Level 14"},
    {   15, "Priority Level 15"},
	{	0, NULL }
};

static void
dissect_ansi_map_pacaindicator(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree){

	int offset = 0;
    proto_item *item;
    proto_tree *subtree;

	item = get_ber_last_created_item();
	subtree = proto_item_add_subtree(item, ett_pacaindicator);
	/* PACA Level (octet 1, bits B-E) */
	proto_tree_add_item(subtree, hf_ansi_map_PACA_Level, tvb, offset,	1, FALSE);
	/* Permanent Activation (PA) (octet 1, bit A) */
	proto_tree_add_item(subtree, hf_ansi_map_pacaindicator_pa, tvb, offset,	1, FALSE);
}

/* 6.5.2.92 PageIndicator */
static const value_string ansi_map_PageIndicator_vals[]  = {
    {   0, "Not used"},
    {   1, "Page"},
    {   2, "Listen only"},
	{	0, NULL }
};

/* 6.5.2.93 PC_SSN */
static void
dissect_ansi_map_pc_ssn(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree){

	int offset = 0;
    proto_item *item;
    proto_tree *subtree;
	guint8 b1,b2,b3,b4;

	item = get_ber_last_created_item();
	subtree = proto_item_add_subtree(item, ett_billingid);
	/* Type (octet 1) */
	proto_tree_add_item(subtree, hf_ansi_map_msc_type, tvb, offset, 1, FALSE);
	offset++;
	/* Point Code Member Number octet 2 */
	b1 = tvb_get_guint8(tvb,offset);
	offset++;
	/* Point Code Cluster Number octet 3 */
	b2 = tvb_get_guint8(tvb,offset);
	offset++;
	/* Point Code Network Number octet 4 */
	b3 = tvb_get_guint8(tvb,offset);
	offset++;
	/* Subsystem Number (SSN) octet 5 */
	b4 = tvb_get_guint8(tvb,offset);
	proto_tree_add_text(subtree, tvb, offset-3, 4 ,	"Point Code %u-%u-%u  SSN %u",
		b3, b2, b1, b4);

}
/* 6.5.2.94 PilotBillingID */
static void
dissect_ansi_map_pilotbillingid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree){

	int offset = 0;
    proto_item *item;
    proto_tree *subtree;

	item = get_ber_last_created_item();
	subtree = proto_item_add_subtree(item, ett_billingid);
	/* First Originating MarketID octet 1 and 2 */
	proto_tree_add_item(subtree, hf_ansi_map_MarketID, tvb, offset, 2, FALSE);
	offset = offset + 2;
	/* First Originating Switch Number octet 3*/
	proto_tree_add_item(subtree, hf_ansi_map_swno, tvb, offset, 1, FALSE);
	offset++;
	/* ID Number */
	proto_tree_add_item(subtree, hf_ansi_map_idno, tvb, offset, 3, FALSE);
	offset = offset + 3;
	proto_tree_add_item(subtree, hf_ansi_map_segcount, tvb, offset, 1, FALSE);

}
/* 6.5.2.96 PreferredLanguageIndicator */
static const value_string ansi_map_PreferredLanguageIndicator_vals[]  = {
    {   0, "Unspecified"},
    {   1, "English"},
    {   2, "French"},
    {   3, "Spanish"},
    {   4, "German"},
    {   5, "Portuguese"},
	{	0, NULL }
};

/* 6.5.2.106 ReceivedSignalQuality */
/* a. This octet is encoded the same as octet 1 in the SignalQuality parameter (see
		6.5.2.121).
*/
/* 6.5.2.118 SetupResult */
static const value_string ansi_map_SetupResult_vals[]  = {
    {   0, "Not used"},
    {   1, "Unsuccessful"},
    {   2, "Successful"},
	{	0, NULL }
};
/* 6.5.2.121 SignalQuality */
/* TODO */

/*	6.5.2.122 SMS_AccessDeniedReason (TIA/EIA-41.5-D, page 5-256)
	N.S0011-0 v 1.0
 */
static const value_string ansi_map_SMS_AccessDeniedReason_vals[]  = {
    {   0, "Not used"},
    {   1, "Denied"},
    {   2, "Postponed"},
    {   3, "Unavailable"},
    {   4, "Invalid"},
	{	0, NULL }
};


/* 6.5.2.125 SMS_CauseCode (TIA/EIA-41.5-D, page 5-262)
	N.S0011-0 v 1.0
 */
static const value_string ansi_map_SMS_CauseCode_vals[]  = {
    {   0, "Address vacant"},
    {   1, "Address translation failure"},
    {   2, "Network resource shortage"},
    {   3, "Network failure"},
    {   4, "Invalid Teleservice ID"},
    {   5, "Other network problem"},
    {   6, "Unsupported network interface"},
    {   32, "No page response"},
    {   33, "Destination busy"},
    {   34, "No acknowledgment"},
    {   35, "Destination resource shortage"},
    {   36, "SMS delivery postponed"},
    {   37, "Destination out of service"},
    {   38, "Destination no longer at this address"},
    {   39, "Other terminal problem"},
    {   64, "Radio interface resource shortage"},
    {   65, "Radio interface incompatibility"},
    {   66, "Other radio interface problem"},
    {   67, "Unsupported Base Station Capability"},
    {   96, "Encoding problem"},
    {   97, "Service origination denied"},
    {   98, "Service termination denied"},
    {   99, "Supplementary service not supported"},
    {   100, "Service not supported"},
    {   101, "Reserved"},
    {   102, "Missing expected parameter"},
    {   103, "Missing mandatory parameter"},
    {   104, "Unrecognized parameter value"},
    {   105, "Unexpected parameter value"},
    {   106, "User Data size error"},
    {   107, "Other general problems"},
    {   108, "Session not active"},
	{	0, NULL }
};

/* 6.5.2.126 SMS_ChargeIndicator */
/* SMS Charge Indicator (octet 1) */
static const value_string ansi_map_SMS_ChargeIndicator_vals[]  = {
    {   0, "Not used"},
    {   1, "No charge"},
    {   2, "Charge original originator"},
    {   3, "Charge original destination"},
	{	0, NULL }
};
/*	4 through 63 Reserved. Treat the same as value 1, No charge.
	64 through 127 Reserved. Treat the same as value 2, Charge original originator.
	128 through 223 Reserved. Treat the same as value 3, Charge original destination.
	224 through 255 Reserved for TIA/EIA-41 protocol extension. If unknown, treat the same as value 2, Charge
	original originator.
	*/

/* 6.5.2.130 SMS_NotificationIndicator N.S0005-0 v 1.0*/
static const value_string ansi_map_SMS_NotificationIndicator_vals[]  = {
    {   0, "Not used"},
    {   1, "Notify when available"},
    {   2, "Do not notify when available"},
	{	0, NULL }
};

/* 6.5.2.136 SMS_OriginationRestrictions */
/* DEFAULT (octet 1, bits A and B) */

static const value_string ansi_map_SMS_OriginationRestrictions_default_vals[]  = {
    {   0, "Block all"},
    {   1, "Reserved"},
    {   1, "Allow specific"},
    {   1, "Allow all"},
	{	0, NULL }
};
/* DIRECT (octet 1, bit C) */
static const true_false_string ansi_map_SMS_OriginationRestrictions_direct_bool_val  = {
  "Allow Direct",
  "Block Direct"
};

/* Force Message Center (FMC) (octet 1, bit D) */
static const true_false_string ansi_map_SMS_OriginationRestrictions_fmc_bool_val  = {
  "Force Indirect",
  "No effect"
};

/* 6.5.2.137 SMS_TeleserviceIdentifier */
/* Updated with N.S0011-0 v 1.0 */

/* SMS Teleservice Identifier (octets 1 and 2) */
static const value_string ansi_map_SMS_TeleserviceIdentifier_vals[]  = {
    {     0, "Not used"},
    {     1, "Reserved for maintenance"},
    {     2, "SSD Update no response"},
    {     3, "SSD Update successful"},
    {     4, "SSD Update failed"},
    {  4096, "AMPS Extended Protocol Enhanced Services" },
    {  4097, "CDMA Cellular Paging Teleservice" },
    {  4098, "CDMA Cellular Messaging Teleservice" },
    {  4099, "CDMA Voice Mail Notification" },
    { 32513, "TDMA Cellular Messaging Teleservice" },
    { 32520, "TDMA System Assisted Mobile Positioning through Satellite (SAMPS)" },
    { 32584, "TDMA Segmented System Assisted Mobile Positioning Service" },
	{	0, NULL }
};
/* 6.5.2.140 SPINITriggers */
/* All Origination (All) (octet 1, bit A) */

/* 6.5.2.142 SSDUpdateReport */
static const value_string ansi_map_SSDUpdateReport_vals[]  = {
    {   0, "Not used"},
    {   4096, "AMPS Extended Protocol Enhanced Services"},
    {   4097, "CDMA Cellular Paging Teleservice"},
    {   4098, "CDMA Cellular Messaging Teleservice"},
    {   32513, "TDMA Cellular Messaging Teleservice"},
    {   32514, "TDMA Cellular Paging Teleservice (CPT-136)"},
    {   32515, "TDMA Over-the-Air Activation Teleservice (OATS)"},
    {   32516, "TDMA Over-the-Air Programming Teleservice (OPTS)"},
    {   32517, "TDMA General UDP Transport Service (GUTS)"},
    {   32576, "Reserved"},
    {   32577, "TDMA Segmented Cellular MessagingTeleservice"},
    {   32578, "TDMA Segmented Cellular Paging Teleservice"},
    {   32579, "TDMA Segmented Over-the-Air Activation Teleservice (OATS)"},
    {   32580, "TDMA Segmented Over-the-Air Programming Teleservice (OPTS)."},
    {   32581, "TDMA Segmented General UDP Transport Service (GUTS)"},
    {   32576, "Reserved"},
	{	0, NULL }
};

/* 6.5.2.143 StationClassMark */

/* 6.5.2.144 SystemAccessData */

/* 6.5.2.146 SystemCapabilities */
/* Updated in N.S0008-0 v 1.0 */
static const true_false_string ansi_map_systemcapabilities_auth_bool_val  = {
  "Authentication parameters were requested on this system access (AUTH=1 in the OMT)",
  "Authentication parameters were not requested on this system access (AUTH=0 in the OMT)."
};

static const true_false_string ansi_map_systemcapabilities_se_bool_val  = {
  "Signaling Message Encryption supported by the system",
  "Signaling Message Encryption not supported by the system"
};

static const true_false_string ansi_map_systemcapabilities_vp_bool_val  = {
  "Voice Privacy supported by the system",
  "Voice Privacy not supported by the system"
};

static const true_false_string ansi_map_systemcapabilities_cave_bool_val  = {
  "System can execute the CAVE algorithm and share SSD for the indicated MS",
  "System cannot execute the CAVE algorithm and cannot share SSD for the indicated MS"
};

static const true_false_string ansi_map_systemcapabilities_ssd_bool_val  = {
  "SSD is shared with the system for the indicated MS",
  "SSD is not shared with the system for the indicated MS"
};

static const true_false_string ansi_map_systemcapabilities_dp_bool_val  = {
  "DP is supported by the system",
  "DP is not supported by the system"
};

static void
dissect_ansi_map_systemcapabilities(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree){

	int offset = 0;
    proto_item *item;
    proto_tree *subtree;

	item = get_ber_last_created_item();
	subtree = proto_item_add_subtree(item, ett_systemcapabilities);
	proto_tree_add_item(subtree, hf_ansi_map_reservedBitHG, tvb, offset, 1, FALSE);
	proto_tree_add_item(subtree, hf_ansi_map_systemcapabilities_dp, tvb, offset, 1, FALSE);
	proto_tree_add_item(subtree, hf_ansi_map_systemcapabilities_ssd, tvb, offset, 1, FALSE);
	proto_tree_add_item(subtree, hf_ansi_map_systemcapabilities_cave, tvb, offset, 1, FALSE);
	proto_tree_add_item(subtree, hf_ansi_map_systemcapabilities_vp, tvb, offset, 1, FALSE);
	proto_tree_add_item(subtree, hf_ansi_map_systemcapabilities_se, tvb, offset, 1, FALSE);
	proto_tree_add_item(subtree, hf_ansi_map_systemcapabilities_auth, tvb, offset, 1, FALSE);
}

/* 6.5.2.151 TDMABurstIndicator */
/* 6.5.2.152 TDMACallMode */
/* 6.5.2.153 TDMAChannelData Updated in N.S0007-0 v 1.0*/

/* 6.5.2.155 TerminationAccessType */
/* XXX Fix Me, Fill up the values or do special decoding? */
static const value_string ansi_map_TerminationAccessType_vals[]  = {
    {   0, "Not used"},
    {   1, "Reserved for controlling system assignment (may be a trunk group identifier)."},
		/* 1 through  127 */
    {   127, "Reserved for controlling system assignment (may be a trunk group identifier)."},
    {   128, "Reserved for TIA/EIA-41 protocol extension. If unknown, treat the same as value 253, Land-to-Mobile Directory Number access"},
		/* 128 through  160 */
    {   160, "Reserved for TIA/EIA-41 protocol extension. If unknown, treat the same as value 253, Land-to-Mobile Directory Number access"},
    {   161, "Reserved for this Standard"},
		/* 161 through  251 */
    {   151, "Reserved for this Standard"},
    {   252, "Mobile-to-Mobile Directory Number access"},
    {   253, "Land-to-Mobile Directory Number access"},
    {   254, "Remote Feature Control port access"},
    {   255, "Roamer port access"},
	{	0, NULL }
};

/* 6.5.2.158 TerminationTreatment */
static const value_string ansi_map_TerminationTreatment_vals[]  = {
    {   0, "Not used"},
    {   1, "MS Termination"},
    {   2, "Voice Mail Storage"},
    {   3, "Voice Mail Retrieval"},
    {   4, "Dialogue Termination"},
	{	0, NULL }
};

/* 6.5.2.159 TerminationTriggers */
/* Busy (octet 1, bits A and B) */
static const value_string ansi_map_terminationtriggers_busy_vals[]  = {
    {   0, "Busy Call"},
    {   1, "Busy Trigger"},
    {   2, "Busy Leg"},
    {   3, "Reserved. Treat as an unrecognized parameter value"},
	{	0, NULL }
};
/* Routing Failure (RF) (octet 1, bits C and D) */
static const value_string ansi_map_terminationtriggers_rf_vals[]  = {
    {   0, "Failed Call"},
    {   1, "Routing Failure Trigger"},
    {   2, "Failed Leg"},
    {   3, "Reserved. Treat as an unrecognized parameter value"},
	{	0, NULL }
};
/* No Page Response (NPR) (octet 1, bits E and F) */
static const value_string ansi_map_terminationtriggers_npr_vals[]  = {
    {   0, "No Page Response Call"},
    {   1, "No Page Response Trigger"},
    {   2, "No Page Response Leg"},
    {   3, "Reserved. Treat as an unrecognized parameter value"},
	{	0, NULL }
};
/* No Answer (NA) (octet 1, bits G and H) */
static const value_string ansi_map_terminationtriggers_na_vals[]  = {
    {   0, "No Answer Call"},
    {   1, "No Answer Trigger"},
    {   2, "No Answer Leg"},
    {   3, "Reserved"},
	{	0, NULL }
};
/* None Reachable (NR) (octet 2, bit A) */
static const value_string ansi_map_terminationtriggers_nr_vals[]  = {
    {   0, "Member Not Reachable"},
    {   1, "Group Not Reachable"},
	{	0, NULL }
};

/* 6.5.2.159 TerminationTriggers N.S0005-0 v 1.0*/
static void
dissect_ansi_map_terminationtriggers(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree){

	int offset = 0;
    proto_item *item;
    proto_tree *subtree;

	item = get_ber_last_created_item();
	subtree = proto_item_add_subtree(item, ett_transactioncapability);

	proto_tree_add_item(subtree, hf_ansi_map_reservedBitH, tvb, offset, 1, FALSE);	
	/* No Page Response (NPR) (octet 1, bits E and F) */
	proto_tree_add_item(subtree, hf_ansi_map_terminationtriggers_npr, tvb, offset, 1, FALSE);
	/* No Answer (NA) (octet 1, bits G and H) */
	proto_tree_add_item(subtree, hf_ansi_map_terminationtriggers_na, tvb, offset, 1, FALSE);
	/* Routing Failure (RF) (octet 1, bits C and D) */
	proto_tree_add_item(subtree, hf_ansi_map_terminationtriggers_rf, tvb, offset, 1, FALSE);
	/* Busy (octet 1, bits A and B) */
	proto_tree_add_item(subtree, hf_ansi_map_terminationtriggers_busy, tvb, offset, 1, FALSE);
	offset++;

	/* None Reachable (NR) (octet 2, bit A) */
	proto_tree_add_item(subtree, hf_ansi_map_terminationtriggers_nr, tvb, offset, 1, FALSE);
}

/* 6.5.2.160 TransactionCapability (TIA/EIA-41.5-D, page 5-315) */
/* Updated with N.S0010-0 v 1.0, N.S0012-0 v 1.0 N.S0013-0 v 1.0 */
static const true_false_string ansi_map_trans_cap_prof_bool_val  = {
  "The system is capable of supporting the IS-41-C profile parameters",
  "The system is not capable of supporting the IS-41-C profile parameters"
};

static const true_false_string ansi_map_trans_cap_busy_bool_val  = {
  "The system is capable of detecting a busy condition at the current time",
  "The system is not capable of detecting a busy condition at the current time"
};

static const true_false_string ansi_map_trans_cap_ann_bool_val  = {
  "The system is capable of honoring the AnnouncementList parameter at the current time",
  "The system is not capable of honoring the AnnouncementList parameter at the current time"
};

static const true_false_string ansi_map_trans_cap_rui_bool_val  = {
  "The system is capable of interacting with the user",
  "The system is not capable of interacting with the user"
};

static const true_false_string ansi_map_trans_cap_spini_bool_val  = {
  "The system is capable of supporting local SPINI operation",
  "The system is not capable of supporting local SPINI operation at the current time"
};

static const true_false_string ansi_map_trans_cap_uzci_bool_val  = {
  "The system is User Zone capable at the current time",
  "The system is not User Zone capable at the current time"
};
static const true_false_string ansi_map_trans_cap_ndss_bool_val  = {
  "Serving system is NDSS capable",
  "Serving system is not NDSS capable"
};
static const true_false_string ansi_map_trans_cap_nami_bool_val  = {
  "The system is CNAP/CNAR capable",
  "The system is not CNAP/CNAR capable"
};

static const value_string ansi_map_trans_cap_multerm_vals[]  = {
    {   0, "The system cannot accept a termination at this time (i.e., cannot accept routing information)"},
    {   1, "The system supports the number of call legs indicated"},
    {   2, "The system supports the number of call legs indicated"},
    {   3, "The system supports the number of call legs indicated"},
    {   4, "The system supports the number of call legs indicated"},
    {   5, "The system supports the number of call legs indicated"},
    {   6, "The system supports the number of call legs indicated"},
    {   7, "The system supports the number of call legs indicated"},
    {   8, "The system supports the number of call legs indicated"},
    {   9, "The system supports the number of call legs indicated"},
    {   10, "The system supports the number of call legs indicated"},
    {   11, "The system supports the number of call legs indicated"},
    {   12, "The system supports the number of call legs indicated"},
    {   13, "The system supports the number of call legs indicated"},
    {   14, "The system supports the number of call legs indicated"},
    {   15, "The system supports the number of call legs indicated"},
	{	0, NULL }
};

static const true_false_string ansi_map_trans_cap_tl_bool_val  = {
  "The system is capable of supporting the TerminationList parameter at the current time",
  "The system is not capable of supporting the TerminationList parameter at the current time"
};

static const true_false_string ansi_map_trans_cap_waddr_bool_val  = {
  "The system is capable of supporting the TriggerAddressList parameter",
  "The system is not capable of supporting the TriggerAddressList parameter"
};


static void
dissect_ansi_map_transactioncapability(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree){

	int offset = 0;
    proto_item *item;
    proto_tree *subtree;

	item = get_ber_last_created_item();
	subtree = proto_item_add_subtree(item, ett_transactioncapability);

	/*NAME Capability Indicator (NAMI) (octet 1, bit H) */
	proto_tree_add_item(subtree, hf_ansi_map_trans_cap_nami, tvb, offset, 1, FALSE);
	/* NDSS Capability (NDSS) (octet 1, bit G) */
	proto_tree_add_item(subtree, hf_ansi_map_trans_cap_ndss, tvb, offset, 1, FALSE);
	/* UZ Capability Indicator (UZCI) (octet 1, bit F) */
	proto_tree_add_item(subtree, hf_ansi_map_trans_cap_uzci, tvb, offset, 1, FALSE);
	/* Subscriber PIN Intercept (SPINI) (octet 1, bit E) */
	proto_tree_add_item(subtree, hf_ansi_map_trans_cap_spini, tvb, offset, 1, FALSE);
	/* Remote User Interaction (RUI) (octet 1, bit D) */
	proto_tree_add_item(subtree, hf_ansi_map_trans_cap_rui, tvb, offset, 1, FALSE);
	/* Announcements (ANN) (octet 1, bit C) */
	proto_tree_add_item(subtree, hf_ansi_map_trans_cap_ann, tvb, offset, 1, FALSE);
	/* Busy Detection (BUSY) (octet 1, bit B) */
	proto_tree_add_item(subtree, hf_ansi_map_trans_cap_busy, tvb, offset, 1, FALSE);
	/* Profile (PROF) (octet 1, bit A) */
	proto_tree_add_item(subtree, hf_ansi_map_trans_cap_prof, tvb, offset, 1, FALSE);
	offset++;

	/* WIN Addressing (WADDR) (octet 2, bit F) */
	proto_tree_add_item(subtree, hf_ansi_trans_cap_waddr, tvb, offset, 1, FALSE);
	/* TerminationList (TL) (octet 2, bit E) */
	proto_tree_add_item(subtree, hf_ansi_trans_cap_tl, tvb, offset, 1, FALSE);
	/* Multiple Terminations (octet 2, bits A-D) */
	proto_tree_add_item(subtree, hf_ansi_trans_cap_multerm, tvb, offset, 1, FALSE);
}

/* 6.5.2.162 UniqueChallengeReport */
/* Unique Challenge Report (octet 1) */
static const value_string ansi_map_UniqueChallengeReport_vals[]  = {
    {   0, "Not used"},
    {   1, "Unique Challenge not attempted"},
    {   2, "Unique Challenge no response"},
    {   3, "Unique Challenge successful"},
    {   4, "Unique Challenge failed"},
	{	0, NULL }
};

/* 6.5.2.166 VoicePrivacyMask */


/* 6.5.2.e (TSB76) CDMAServiceConfigurationRecord N.S0008-0 v 1.0 */
/* a. This field carries the CDMA Service Configuration Record. The bit-layout is the
same as that of Service Configuration Record in TSB74, and J-STD-008.
*/

/* 6.5.2.f CDMAServiceOption N.S0010-0 v 1.0 */

/* values copied from old ANSi map dissector */
static const range_string cdmaserviceoption_vals[] = {
	{ 1, 1, "Basic Variable Rate Voice Service (8 kbps)" }, 
	{ 2, 2, "Mobile Station Loopback (8 kbps)" }, 
	{ 3, 3, "Enhanced Variable Rate Voice Service (8 kbps)" }, 
	{ 4, 4, "Asynchronous Data Service (9.6 kbps)" }, 
	{ 5, 5, "Group 3 Facsimile (9.6 kbps)" },
	{ 6, 6, "Short Message Services (Rate Set 1)" }, 
	{ 7, 7, "Packet Data Service: Internet or ISO Protocol Stack (9.6 kbps)" }, 
	{ 8, 8, "Packet Data Service: CDPD Protocol Stack (9.6 kbps)" }, 
	{ 9, 9, "Mobile Station Loopback (13 kbps)" }, 
	{ 10, 10, "STU-III Transparent Service" }, 
	{ 11, 11, "STU-III Non-Transparent Service" }, 
	{ 12, 12, "Asynchronous Data Service (14.4 or 9.6 kbps)" }, 
	{ 13, 13, "Group 3 Facsimile (14.4 or 9.6 kbps)" }, 
	{ 14, 14, "Short Message Services (Rate Set 2)" }, 
	{ 15, 15, "Packet Data Service: Internet or ISO Protocol Stack (14.4 kbps)" }, 
	{ 16, 16, "Packet Data Service: CDPD Protocol Stack (14.4 kbps)" }, 
	{ 17, 17, "High Rate Voice Service (13 kbps)" }, 
	{ 18, 18, "Over-the-Air Parameter Administration (Rate Set 1)" }, 
	{ 19, 19, "Over-the-Air Parameter Administration (Rate Set 2)" }, 
	{ 20, 20, "Group 3 Analog Facsimile (Rate Set 1)" }, 
	{ 21, 21, "Group 3 Analog Facsimile (Rate Set 2)" }, 
	{ 22, 22, "High Speed Packet Data Service: Internet or ISO Protocol Stack (RS1 forward, RS1 reverse)" }, 
	{ 23, 23, "High Speed Packet Data Service: Internet or ISO Protocol Stack (RS1 forward, RS2 reverse)" }, 
	{ 24, 24, "High Speed Packet Data Service: Internet or ISO Protocol Stack (RS2 forward, RS1 reverse)" }, 
	{ 25, 25, "High Speed Packet Data Service: Internet or ISO Protocol Stack (RS2 forward, RS2 reverse)" },
	{ 26, 26, "High Speed Packet Data Service: CDPD Protocol Stack (RS1 forward, RS1 reverse)" }, 
	{ 27, 27, "High Speed Packet Data Service: CDPD Protocol Stack (RS1 forward, RS2 reverse)" }, 
	{ 28, 28, "High Speed Packet Data Service: CDPD Protocol Stack (RS2 forward, RS1 reverse)" }, 
	{ 29, 29, "High Speed Packet Data Service: CDPD Protocol Stack (RS2 forward, RS2 reverse)" }, 
	{ 30, 30, "Supplemental Channel Loopback Test for Rate Set 1" }, 
	{ 31, 31, "Supplemental Channel Loopback Test for Rate Set 2" }, 
	{ 32, 32, "Test Data Service Option (TDSO)" }, 
	{ 33, 33, "cdma2000 High Speed Packet Data Service, Internet or ISO Protocol Stack" }, 
	{ 34, 34, "cdma2000 High Speed Packet Data Service, CDPD Protocol Stack" }, 
	{ 35, 35, "Location Services, Rate Set 1 (9.6 kbps)" },
	{ 36, 36, "Location Services, Rate Set 2 (14.4 kbps)" }, 
	{ 37, 37, "ISDN Interworking Service (64 kbps)" }, 
	{ 38, 38, "GSM Voice" }, 
	{ 39, 39, "GSM Circuit Data" }, 
	{ 40, 40, "GSM Packet Data" }, 
	{ 41, 41, "GSM Short Message Service" }, 
	{ 42, 42, "None Reserved for MC-MAP standard service options" }, 
	{ 54, 54, "Markov Service Option (MSO)" }, 
	{ 55, 55, "Loopback Service Option (LSO)" },
	{ 56, 56, "Selectable Mode Vocoder" }, 
	{ 57, 57, "32 kbps Circuit Video Conferencing" }, 
	{ 58, 58, "64 kbps Circuit Video Conferencing" }, 
	{ 59, 59, "HRPD Accounting Records Identifier" }, 
	{ 60, 60, "Link Layer Assisted Robust Header Compression (LLA ROHC) - Header Removal" }, 
	{ 61, 61, "Link Layer Assisted Robust Header Compression (LLA ROHC) - Header Compression" }, 
	{ 62, 4099, "None Reserved for standard service options" }, 
	{ 4100, 4100, "Asynchronous Data Service, Revision 1 (9.6 or 14.4 kbps)" }, 
	{ 4101, 4101, "Group 3 Facsimile, Revision 1 (9.6 or 14.4 kbps)" }, 
	{ 4102, 4102, "Reserved for standard service option" },
	{ 4103, 4103, "Packet Data Service: Internet or ISO Protocol Stack, Revision 1 (9.6 or 14.4 kbps)" }, 
	{ 4104, 4104, "Packet Data Service: CDPD Protocol Stack, Revision 1 (9.6 or 14.4 kbps)" }, 
	{ 4105, 32767, "Reserved for standard service options" }, 
	{ 32768, 32768, "QCELP (13 kbps)" }, 
	{ 32769, 32771, "Proprietary QUALCOMM Incorporated" }, 
	{ 32772, 32775, "Proprietary OKI Telecom" }, 
	{ 32776, 32779, "Proprietary Lucent Technologies" }, 
	{ 32780, 32783, "Nokia" }, 
	{ 32784, 32787, "NORTEL NETWORKS" }, 
	{ 32788, 32791, "Sony Electronics Inc" }, 
	{ 32792, 32795, "Motorola" }, 
	{ 32796, 32799, "QUALCOMM Incorporated" }, 
	{ 32800, 32803, "QUALCOMM Incorporated" }, 
	{ 32804, 32807, "QUALCOMM Incorporated" }, 
	{ 32808, 32811, "QUALCOMM Incorporated" }, 
	{ 32812, 32815, "Lucent Technologies" }, 
	{ 32816, 32819, "Denso International" }, 
	{ 32820, 32823, "Motorola" }, 
	{ 32824, 32827, "Denso International" }, 
	{ 32828, 32831, "Denso International" }, 
	{ 32832, 32835, "Denso International" }, 
	{ 32836, 32839, "NEC America" },
	{ 32840, 32843, "Samsung Electrnics" },
	{ 32844, 32847, "Texas Instruments Incorporated" },
	{ 32848, 32851, "Toshiba Corporation" },
	{ 32852, 32855, "LG Electronics Inc." },
	{ 32856, 32859, "VIA Telecom Inc." },
	{ 0,           0,          NULL                   }
};

static void
dissect_ansi_map_cdmaserviceoption(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree){

	int offset = 0;
    proto_item *item;
    proto_tree *subtree;
	guint16 so;

	item = get_ber_last_created_item();
	subtree = proto_item_add_subtree(item, ett_cdmaserviceoption);

	so = tvb_get_ntohs(tvb,offset);
    proto_tree_add_uint_format(subtree, hf_ansi_map_cdmaserviceoption,
					       tvb, offset, 2, so,
					       "CDMAServiceOption: %u %s", so,
					       rval_to_str(so,cdmaserviceoption_vals ,"Unknown"));


}
/* 6.5.2.f (TSB76) CDMAServiceOption N.S0008-0 v 1.0*/
/* This field carries the CDMA Service Option. The bit-layout is the same as that of
Service Option in TSB74 and J-STD-008.*/

/* 6.5.2.i (IS-730) TDMAServiceCode N.S0008-0 v 1.0 */
static const value_string ansi_map_TDMAServiceCode_vals[]  = {
    {   0, "Analog Speech Only"},
    {   1, "Digital Speech Only"},
    {   2, "Analog or Digital Speech, Analog Preferred"},
    {   3, "Analog or Digital Speech, Digital Preferred"},
    {   4, "Asynchronous Data"},
    {   5, "G3 Fax"},
    {   6, "Not Used (Service Rejected)"},
    {   7, "STU-III"},
	{	0, NULL }
};
/* 6.5.2.j (IS-730) TDMATerminalCapability N.S0008-0 v 1.0 Updted with N.S0015-0 */
/* Supported Frequency Band (octet 1) */
/* Voice Coder (octet 2) */
/* Protocol Version (octet 3) N.S0015-0 */
static const value_string ansi_map_TDMATerminalCapability_prot_ver_vals[]  = {
    {   0, "EIA-553 or IS-54-A"},
    {   1, "TIA/EIA-627.(IS-54-B)"},
    {   2, "IS-136"},
    {   3, "Permanently Reserved (ANSI J-STD-011).Treat the same as value 4, IS-136-A."},
    {   4, "PV 0 as published in TIA/EIA-136-0 and IS-136-A."},
    {   5, "PV 1 as published in TIA/EIA-136-A."},
    {   6, "PV 2 as published in TIA/EIA-136-A."},
    {   7, "PV 3 as published in TIA/EIA-136-A."},
	{	0, NULL }
};
/* Asynchronous Data (ADS) (octet 4, bit A) N.S0007-0*/
/* Group 3 Fax (G3FAX) (octet 4, bit B) */
/* Secure Telephone Unit III (STU3) (octet 4, bit C) */
/* Analog Voice (AVOX) (octet 4, bit D) */
/* Half Rate (HRATE) (octet 4, bit E) */
/* Full Rate (FRATE) (octet 4, bit F) */
/* Double Rate (2RATE) (octet 4, bit G) */
/* Triple Rate (3RATE) (octet 4, bit H) */


/* 6.5.2.k (IS-730)) TDMAVoiceCoder N.S0008-0 v 1.0, N.S0007-0 */
/* VoiceCoder (octet 1) */

/* 6.5.2.p UserZoneData N.S0015-0 */

/* 6.5.2.aa BaseStationManufacturerCode N.S0007-0 v 1.0 */
/* The BaseStationManufacturerCode (BSMC) parameter specifies the manufacturer of the
base station that is currently serving the MS (see IS-136 for enumeration of values).*/

/* 6.5.2.ab BSMCStatus */

/* BSMC Status (octet 1) */
static const value_string ansi_map_BSMCStatus_vals[]  = {
    {   0, "Same BSMC Value shall not be supported"},
    {   1, "Same BSMC Value shall be supported"},
	{	0, NULL }
};

/*- 6.5.2.ac ControlChannelMode (N.S0007-0 v 1.0)*/
static const value_string ansi_map_ControlChannelMode_vals[]  = {
    {   0, "Unknown"},
    {   1, "MS is in Analog CC Mode"},
    {   2, "MS is in Digital CC Mode"},
    {   3, "MS is in NAMPS CC Mode"},
	{	0, NULL }
};

/* 6.5.2.ad NonPublicData N.S0007-0 v 1.0*/
/* NP Only Service (NPOS) (octet 1, bits A and B) */
/* Charging Area Tone Service (CATS) (octet 1, bits C - F) */
/* PSID/RSID Download Order (PRDO) (octet 1, bits G and H) */

/* 6.5.2.ae PagingFrameClass N.S0007-0 v 1.0*/
/* Paging Frame Class (octet 1) */

static const value_string ansi_map_PagingFrameClass_vals[]  = {
    {   0, "PagingFrameClass 1 (1.28 seconds)"},
    {   1, "PagingFrameClass 2 (2.56 seconds)"},
    {   2, "PagingFrameClass 3 (3.84 seconds)"},
    {   3, "PagingFrameClass 4 (7.68 seconds)"},
    {   4, "PagingFrameClass 5 (15.36 seconds)"},
    {   5, "PagingFrameClass 6 (30.72 seconds)"},
    {   6, "PagingFrameClass 7 (61.44 seconds)"},
    {   7, "PagingFrameClass 8 (122.88 seconds)"},
    {   8, "Reserved. Treat the same as value 0, PagingFrameClass 1"},
	{	0, NULL }
};

/* 6.5.2.af PSID_RSIDInformation N.S0007-0 v 1.0*/
/* PSID/RSID Indicator (octet 1, bit A) */
/* PSID/RSID Type (octet 1, bits B-D) */

/* 6.5.2.ah ServicesResult N.S0007-0 v 1.0*/
/* PSID/RSID Download Result (PRDR) (octet 1, bits A and B) */
static const value_string ansi_map_ServicesResult_ppr_vals[]  = {
    {   0, "No Indication"},
    {   1, "Unsuccessful PSID/RSID download"},
    {   2, "Successful PSID/RSID download"},
    {   3, "Reserved. Treat the same as value 0, No Indication"},
	{	0, NULL }
};

/* 6.5.2.ai SOCStatus N.S0007-0 v 1.0*/

/* SOC Status (octet 1) */
static const value_string ansi_map_SOCStatus_vals[]  = {
    {   0, "Same SOC Value shall not be supported"},
    {   1, "Same SOC Value shall be supported"},
	{	0, NULL }
};

/* 6.5.2.aj SystemOperatorCode N.S0007-0 v 1.0*/
/* The SystemOperatorCode (SOC) parameter specifies the system operator that is currently
providing service to a MS (see IS-136 for enumeration of values) */

/* 6.5.2.al UserGroup N.S0007-0 v 1.0*/

/* 6.5.2.am UserZoneData N.S0007-0 v 1.0*/


/*Table 6.5.2.ay TDMABandwidth value N.S0008-0 v 1.0 */
static const value_string ansi_map_TDMABandwidth_vals[]  = {
    {   0, "Half-Rate Digital Traffic Channel Only"},
    {   1, "Full-Rate Digital Traffic Channel Only"},
    {   2, "Half-Rate or Full-rate Digital Traffic Channel - Full-Rate Preferred"},
    {   3, "Half-rate or Full-rate Digital Traffic Channel - Half-rate Preferred"},
    {   4, "Double Full-Rate Digital Traffic Channel Only"},
    {   5, "Triple Full-Rate Digital Traffic Channel Only"},
    {   6, "Reserved. Treat reserved values the same as value 1 - Full-Rate Digital Traffic Channel Only"},
    {   7, "Reserved. Treat reserved values the same as value 1 - Full-Rate Digital Traffic Channel Only"},
    {   8, "Reserved. Treat reserved values the same as value 1 - Full-Rate Digital Traffic Channel Only"},
    {   9, "Reserved. Treat reserved values the same as value 1 - Full-Rate Digital Traffic Channel Only"},
    {   10, "Reserved. Treat reserved values the same as value 1 - Full-Rate Digital Traffic Channel Only"},
    {   11, "Reserved. Treat reserved values the same as value 1 - Full-Rate Digital Traffic Channel Only"},
    {   12, "Reserved. Treat reserved values the same as value 1 - Full-Rate Digital Traffic Channel Only"},
    {   13, "Reserved. Treat reserved values the same as value 1 - Full-Rate Digital Traffic Channel Only"},
    {   14, "Reserved. Treat reserved values the same as value 1 - Full-Rate Digital Traffic Channel Only"},
    {   15, "Reserved. Treat reserved values the same as value 1 - Full-Rate Digital Traffic Channel Only"},
	{	0, NULL }

};

/* 6.5.2.az TDMADataFeaturesIndicator N.S0008-0 v 1.0 */
/* TDMADataFeaturesIndicator 
ansi_map_FeatureActivity_vals

 ADS FeatureActivity ADS-FA ( octet 1 bit A and B )
 G3 Fax FeatureActivity G3FAX-FA ( octet 1 bit C and D )
 STU-III FeatureActivity STUIII-FA ( octet 1 bit E and F )
 Half Rate data FeatureActivity HRATE-FA ( octet 2 bit A and B )
 Full Rate data FeatureActivity FRATE-FA ( octet 2 bit C and D )
 Double Rate data FeatureActivity 2RATE-FA ( octet 2 bit E and F )
 Triple Rate data FeatureActivity 3RATE-FA ( octet g bit G and H )

 Table 6.5.2.azt TDMADataFeaturesIndicator value
 static const value_string ansi_map_TDMADataFeaturesIndicator_vals[]  = {
    {   0, "Not Used"},
    {   1, "Not Authorized"},
    {   2, "Authorized, but de-activated"},
    {   3, "Authorized and activated"},
 	{	0, NULL }

};
*/

/* 6.5.2.ba TDMADataMode N.S0008-0 v 1.0*/

/* 6.5.2.bb TDMAVoiceMode */

/* 6.5.2.bb CDMAConnectionReference N.S0008-0 v 1.0 */
/* Service Option Connection Reference Octet 1 */
/*	a. This field carries the CDMA Service Option Connection Reference. The bitlayout
		is the same as that of Service Option Connection Reference in TSB74 and
		J-STD-008.
*/

/* 6.5.2.ad CDMAState N.S0008-0 v 1.0 */
/* Service Option State Octet 1 */
/* a. This field carries the CDMA Service Option State information. The CDMA
Service Option State is defined in the current CDMA Service Options standard.
If CDMA Service Option State is not explicitly defined within a section of the
relevant CDMA Service Option standard, the CDMA Service Option State shall
carry the value of the ORD_Q octet of all current Service Option Control Orders
(see IS-95), or the contents of all current CDMA Service Option Control
Messages (see TSB74) type specific field for this connection reference. */

/* 6.5.2.aj SecondInterMSCCircuitID */
/* -- XXX Same code as ISLPinformation???
dissect_ansi_map_secondintermsccircuitid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree){

	int offset = 0;
    proto_item *item;
    proto_tree *subtree;

	item = get_ber_last_created_item();
	subtree = proto_item_add_subtree(item, ett_billingid);
	/ Trunk Group Number (G) Octet 1 /
	proto_tree_add_item(subtree, hf_ansi_map_tgn, tvb, offset, 1, FALSE);
	offset++;
	/ Trunk Member Number (M) Octet2 /
	proto_tree_add_item(subtree, hf_ansi_map_tmn, tvb, offset, 1, FALSE);
}
*/
/* 6.5.2.as ChangeServiceAttributes N.S0008-0 v 1.0 */
/* Change Facilities Flag (CHGFAC)(octet 1, bits A - B) */
static const value_string ansi_map_ChangeServiceAttributes_chgfac_vals[]  = {
    {   0, "Change Facilities Operation Requested"},
    {   1, "Change Facilities Operation Not Requested"},
    {   2, "Change Facilities Operation Used"},
    {   3, "Change Facilities Operation Not Used"},
	{	0, NULL }
};
/* Service Negotiate Flag (SRVNEG)(octet 1, bits C - D) */
static const value_string ansi_map_ChangeServiceAttributes_srvneg_vals[]  = {
    {   0, "Service Negotiation Used"},
    {   1, "Service Negotiation Not Used"},
    {   2, "Service Negotiation Required"},
    {   3, "Service Negotiation Not Required"},
	{	0, NULL }
};
/* 6.5.2.au DataPrivacyParameters N.S0008-0 v 1.0*/
/* Privacy Mode (PM) (octet 1, Bits A and B) */
static const value_string ansi_map_DataPrivacyParameters_pm_vals[]  = {
    {   0, "Privacy inactive or not supported"},
    {   1, "Privacy Requested or Acknowledged"},
    {   2, "Reserved. Treat reserved values the same as value 0, Privacy inactive or not supported."},
    {   3, "Reserved. Treat reserved values the same as value 0, Privacy inactive or not supported."},
	{	0, NULL }
};
/* Data Privacy Version (PM) (octet 2) */
static const value_string ansi_map_DataPrivacyParameters_data_priv_ver_vals[]  = {
    {   0, "Not used"},
    {   1, "Data Privacy Version 1"},
	{	0, NULL }
};

/* 6.5.2.av ISLPInformation N.S0008-0 v 1.0*/
/* ISLP Type (octet 1) */
static const value_string ansi_map_islp_type_vals[]  = {
    {   0, "No ISLP supported"},
    {   1, "ISLP supported"},
	{	0, NULL }
};
/* 6.5.2.bc AnalogRedirectInfo */
/* Sys Ordering (octet 1, bits A-E) */
/* Ignore CDMA (IC) (octet 1, bit F) */

/* 6.5.2.be CDMAChannelNumber N.S0010-0 v 1.0*/

/* 6.5.2.bg CDMAPowerCombinedIndicator N.S0010-0 v 1.0*/

/* 6.5.2.bi CDMASearchParameters N.S0010-0 v 1.0*/

/* 6.5.2.bk CDMANetworkIdentification N.S0010-0 v 1.0*/
/* See CDMA [J-STD-008] for encoding of this field. */

/* 6.5.2.bo RequiredParametersMask N.S0010-0 v 1.0 */

/* 6.5.2.bp ServiceRedirectionCause */
static const value_string ansi_map_ServiceRedirectionCause_type_vals[]  = {
    {   0, "Not used"},
    {   1, "NormalRegistration"},
    {   2, "SystemNotFound."},
    {   3, "ProtocolMismatch."},
    {   4, "RegistrationRejection."},
    {   5, "WrongSID."},
    {   6, "WrongNID.."},
	{	0, NULL }
};

/* 6.5.2.bq ServiceRedirectionInfo  N.S0010-0 v 1.0 */

/* 6.5.2.br RoamingIndication N.S0010-0 v 1.0*/
/* See CDMA [TSB58] for the definition of this field. */

/* 6.5.2.bw CallingPartyName N.S0012-0 v 1.0*/

/* Presentation Status (octet 1, bits A and B) */
static const value_string ansi_map_Presentation_Status_vals[]  = {
    {   0, "Presentation allowed"},
    {   1, "Presentation restricted"},
    {   2, "Blocking toggle"},
    {   3, "No indication"},
	{	0, NULL }
};
/* Availability (octet 1, bit E) N.S0012-0 v 1.0*/
static const true_false_string ansi_map_Availability_bool_val  = {
  "Name not available",
  "Name available/unknown"
};
static void
dissect_ansi_map_callingpartyname(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree){

	int offset = 0;
    proto_item *item;
    proto_tree *subtree;

	item = get_ber_last_created_item();
	subtree = proto_item_add_subtree(item, ett_callingpartyname);
	/* Availability (octet 1, bit E) N.S0012-0 v 1.0*/

	/* Presentation Status (octet 1, bits A and B) */



}


/* 6.5.2.bx DisplayText N.S0012-0 v 1.0*/
/* a. Refer to ANSI T1.610 for field encoding. */

/* 6.5.2.bz ServiceID
Service Identifier (octets 1 to n)
0 Not used.
1 Calling Name Presentation - No RND.
2 Calling Name Presentation with RND.
 */

/* 6.5.2.co GlobalTitle N.S0013-0 v 1.0
 * Refer to Section 3 of ANSI T1.112 for the encoding of this field.
 */
/* Address Indicator octet 1 */
/* Global Title Octet 2 - n */


/* 6.5.2.dc SpecializedResource N.S0013-0 v 1.0*/
/* Resource Type (octet 1) */
static const value_string ansi_map_resource_type_vals[]  = {
    {   0, "Not used"},
    {   1, "DTMF tone detector"},
    {   2, "Automatic Speech Recognition - Speaker Independent - Digits"},
    {   3, "Automatic Speech Recognition - Speaker Independent - Speech User Interface Version 1"},
	{	0, NULL }
};
/* 6.5.2.df TriggerCapability */
/* Updated with N.S0004 N.S0013-0 v 1.0*/

static const true_false_string ansi_map_triggercapability_bool_val  = {
  "triggers can be armed by the TriggerAddressList parameter",
  "triggers cannot be armed by the TriggerAddressList parameter"
};

static void
dissect_ansi_map_triggercapability(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree){

	int offset = 0;
    proto_item *item;
    proto_tree *subtree;

	item = get_ber_last_created_item();
	subtree = proto_item_add_subtree(item, ett_triggercapability);


	/* O_No_Answer (ONA) (octet 1, bit H)*/
	proto_tree_add_item(subtree, hf_ansi_map_triggercapability_ona, tvb, offset,	1, FALSE);
	/* O_Disconnect (ODISC) (octet 1, bit G)*/
	proto_tree_add_item(subtree, hf_ansi_map_triggercapability_odisc, tvb, offset,	1, FALSE);
	/* O_Answer (OANS) (octet 1, bit F)*/
	proto_tree_add_item(subtree, hf_ansi_map_triggercapability_oans, tvb, offset,	1, FALSE);
	/* Origination_Attempt_Authorized (OAA) (octet 1, bit E)*/
	proto_tree_add_item(subtree, hf_ansi_map_triggercapability_oaa, tvb, offset,	1, FALSE);
	/* Revertive_Call (RvtC) (octet 1, bit D)*/
	proto_tree_add_item(subtree, hf_ansi_map_triggercapability_rvtc, tvb, offset,	1, FALSE);
	/* All_Calls (All) (octet 1, bit C)*/
	proto_tree_add_item(subtree, hf_ansi_map_triggercapability_all, tvb, offset,	1, FALSE);
	/* K-digit (K-digit) (octet 1, bit B)*/
	proto_tree_add_item(subtree, hf_ansi_map_triggercapability_kdigit, tvb, offset,	1, FALSE);
	/* Introducing Star/Pound (INIT) (octet 1, bit A) */
	proto_tree_add_item(subtree, hf_ansi_map_triggercapability_init, tvb, offset,	1, FALSE);
	offset++;


	/* O_Called_Party_Busy (OBSY) (octet 2, bit H)*/
	proto_tree_add_item(subtree, hf_ansi_map_triggercapability_obsy, tvb, offset,	1, FALSE);
	/* Called_Routing_Address_Available (CdRAA) (octet 2, bit G)*/
	proto_tree_add_item(subtree, hf_ansi_map_triggercapability_cdraa, tvb, offset,	1, FALSE);
	/* Initial_Termination (IT) (octet 2, bit F)*/
	proto_tree_add_item(subtree, hf_ansi_map_triggercapability_it, tvb, offset,	1, FALSE);
	/* Calling_Routing_Address_Available (CgRAA)*/
	proto_tree_add_item(subtree, hf_ansi_map_triggercapability_cgraa, tvb, offset,	1, FALSE);
	/* Advanced_Termination (AT) (octet 2, bit D)*/
	proto_tree_add_item(subtree, hf_ansi_map_triggercapability_at, tvb, offset,	1, FALSE);
	/* Prior_Agreement (PA) (octet 2, bit C)*/
	proto_tree_add_item(subtree, hf_ansi_map_triggercapability_pa, tvb, offset,	1, FALSE);
	/* Unrecognized_Number (Unrec) (octet 2, bit B)*/
	proto_tree_add_item(subtree, hf_ansi_map_triggercapability_unrec, tvb, offset,	1, FALSE);
	/* Call Types (CT) (octet 2, bit A)*/
	proto_tree_add_item(subtree, hf_ansi_map_triggercapability_ct, tvb, offset,	1, FALSE);
	offset++;
	/* */
	/* */
	/* */
	/* T_Disconnect (TDISC) (octet 3, bit E)*/
	proto_tree_add_item(subtree, hf_ansi_map_triggercapability_tdisc, tvb, offset,	1, FALSE);
	/* T_Answer (TANS) (octet 3, bit D)*/
	proto_tree_add_item(subtree, hf_ansi_map_triggercapability_tans, tvb, offset,	1, FALSE);
	/* T_No_Answer (TNA) (octet 3, bit C)*/
	proto_tree_add_item(subtree, hf_ansi_map_triggercapability_tna, tvb, offset,	1, FALSE);
	/* T_Busy (TBusy) (octet 3, bit B)*/
	proto_tree_add_item(subtree, hf_ansi_map_triggercapability_tbusy, tvb, offset,	1, FALSE);
	/* Terminating_Resource_Available (TRA) (octet 3, bit A) */
	proto_tree_add_item(subtree, hf_ansi_map_triggercapability_tra, tvb, offset,	1, FALSE);

}
/* 6.5.2.ei DMH_ServiceID N.S0018 */

/* 6.5.2.dj WINOperationsCapability */
/* Updated with N.S0004 */
/* ConnectResource (CONN) (octet 1, bit A) */
static const true_false_string ansi_map_winoperationscapability_conn_bool_val  = {
  "Sender is capable of supporting the ConnectResource, DisconnectResource, ConnectionFailureReport and ResetTimer (SSFT timer) operations",
  "Sender is not capable of supporting the ConnectResource, DisconnectResource,ConnectionFailureReport and ResetTimer (SSFT timer) operations"
};

/* CallControlDirective (CCDIR) (octet 1, bit B) */
static const true_false_string ansi_map_winoperationscapability_ccdir_bool_val  = {
  "Sender is capable of supporting the CallControlDirective operation",
  "Sender is not capable of supporting the CallControlDirective operation"
};

/* PositionRequest (POS) (octet 1, bit C) */
static const true_false_string ansi_map_winoperationscapability_pos_bool_val  = {
  "Sender is capable of supporting the PositionRequest operation",
  "Sender is not capable of supporting the PositionRequest operation"
};
static void
dissect_ansi_map_winoperationscapability(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree){

	int offset = 0;
    proto_item *item;
    proto_tree *subtree;

	item = get_ber_last_created_item();
	subtree = proto_item_add_subtree(item, ett_winoperationscapability);
	
	/* PositionRequest (POS) (octet 1, bit C) */
	proto_tree_add_item(subtree, hf_ansi_map_winoperationscapability_pos, tvb, offset,	1, FALSE);
	/* CallControlDirective (CCDIR) (octet 1, bit B) */
	proto_tree_add_item(subtree, hf_ansi_map_winoperationscapability_ccdir, tvb, offset,	1, FALSE);
	/* ConnectResource (CONN) (octet 1, bit A) */
	proto_tree_add_item(subtree, hf_ansi_map_winoperationscapability_conn, tvb, offset,	1, FALSE);

}

/* 6.5.2.ei TIA/EIA-41.5-D Modifications N.S0018Re */
/* Octet 1,2 1st MarketID */
/* Octet 3 1st MarketSegmentID */
/* Octet 4,5 1st DMH_ServiceID value */
/* Second marcet ID etc */
/* 6.5.2.ek ControlNetworkID N.S0018*/
static void
dissect_ansi_map_controlnetworkid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree){

	int offset = 0;
    proto_item *item;
    proto_tree *subtree;

	item = get_ber_last_created_item();
	subtree = proto_item_add_subtree(item, ett_controlnetworkid);
	/* MarketID octet 1 and 2 */
	proto_tree_add_item(subtree, hf_ansi_map_MarketID, tvb, offset, 2, FALSE);
	offset = offset + 2;
	/* Switch Number octet 3*/
	proto_tree_add_item(subtree, hf_ansi_map_swno, tvb, offset, 1, FALSE);
	offset++;
}


/* 6.5.2.dk WIN_TriggerList N.S0013-0 v 1.0 */

/* 6.5.2.ec DisplayText2 Updated in N.S0015-0*/

/* 6.5.2.eq MSStatus N.S0004 */

/* 6.5.2.er PositionInformationCode N.S0004 */

/* 6.5.2.fd InterMessageTime N.S0015-0*/
/* Timer value (in 10s of seconds) octet 1 */

/* 6.5.2.fe MSIDUsage N.S0015-0 */
/* M and I Report (octet 1, bits A and B) */
static const value_string ansi_MSIDUsage_m_or_i_vals[]  = {
    {   0, "Not used"},
    {   1, "MIN last used"},
    {   2, "IMSI last used"},
    {   3, "Reserved"},
	{	0, NULL }
};

/* 6.5.2.ff NewMINExtension N.S0015-0 */

/* 6.5.2.fv ACGEncountered N.S0023-0 v 1.0 */
/* ACG Encountered (octet 1, bits A-F) */
static const value_string ansi_ACGEncountered_vals[]  = {
    {   0, "PC_SSN"},
    {   1, "1-digit control"},
    {   2, "2-digit control"},
    {   3, "3-digit control"},
    {   4, "4-digit control"},
    {   5, "5-digit control"},
    {   6, "6-digit control"},
    {   7, "7-digit control"},
    {   8, "8-digit control"},
    {   9, "9-digit control"},
    {   10, "10-digit control"},
    {   11, "11-digit control"},
    {   12, "12-digit control"},
    {   13, "13-digit control"},
    {   14, "14-digit control"},
    {   15, "15-digit control"},
	{	0, NULL }
};
/* Control Type (octet 1, bits G-H) */
static const value_string ansi_ACGEncountered_cntrl_type_vals[]  = {
    {   0, "Not used."},
    {   1, "Service Management System Initiated control encountered"},
    {   2, "SCF Overload control encountered"},
    {   3, "Reserved. Treat the same as value 0, Not used."},
	{	0, NULL }
};

/* 6.5.2.fw ControlType N.S0023-0 v 1.0 *



/* 6.5.2.ge QoSPriority N.S0029-0 v1.0*/
/* 6.5.2.xx QOSPriority */
/* Non-Assured Priority (octet 1, bits A-D) */
static const value_string ansi_map_Priority_vals[]  = {
    {   0, "Priority Level 0. This is the lowest level"},
    {   1, "Priority Level 1"},
    {   2, "Priority Level 2"},
    {   3, "Priority Level 3"},
    {   4, "Priority Level 4"},
    {   5, "Priority Level 5"},
    {   6, "Priority Level 6"},
    {   7, "Priority Level 7"},
    {   8, "Priority Level 8"},
    {   8, "Priority Level 9"},
    {   10, "Priority Level 10"},
    {   11, "Priority Level 11"},
    {   12, "Priority Level 12"},
    {   13, "Priority Level 13"},
    {   14, "Reserved"},
    {   15, "Reserved"},
	{	0, NULL }
};
/* Assured Priority (octet 1, bits E-H)*/


/* 6.5.2.gf PDSNAddress N.S0029-0 v1.0*/
/* a. See IOS Handoff Request message for the definition of this field. */

/* 6.5.2.gg PDSNProtocolType N.S0029-0 v1.0*/
/* See IOS Handoff Request message for the definition of this field. */

/* 6.5.2.gh CDMAMSMeasuredChannelIdentity N.S0029-0 v1.0*/

/* 6.5.2.gl CallingPartyCategory N.S0027*/
/* a. Refer to ITU-T Q.763 (Signalling System No. 7  ISDN user part formats and
codes) for encoding of this parameter.
b. Refer to national ISDN user part specifications for definitions and encoding of the
reserved for national use values.
*/
/* 6.5.2.gm CDMA2000HandoffInvokeIOSData N.S0029-0 v1.0*/
/* IOS A1 Element Handoff Invoke Information */


/* 6.5.2.gn CDMA2000HandoffResponseIOSData */
/* IOS A1 Element Handoff Response Information N.S0029-0 v1.0*/

/* 6.5.2.gr CDMAServiceOptionConnectionIdentifier N.S0029-0 v1.0*/



/* 6.5.2.bp-1 ServiceRedirectionCause value */
static const value_string ansi_map_ServiceRedirectionCause_vals[]  = {
    {   0, "Not used"},
    {   1, "NormalRegistration"},
    {   2, "SystemNotFound"},
    {   3, "ProtocolMismatch"},
    {   4, "RegistrationRejection"},
    {   5, "WrongSID"},
    {   6, "WrongNID"},
	{	0, NULL }
};
/* 6.5.2.mT AuthenticationResponseReauthentication N.S0011-0 v 1.0*/

/* 6.5.2.vT ReauthenticationReport N.S0011-0 v 1.0*/
static const value_string ansi_map_ReauthenticationReport_vals[]  = {
    {   0, "Not used"},
    {   1, "Reauthentication not attempted"},
    {   2, "Reauthentication no response"},
    {   3, "Reauthentication successful"},
    {   4, "RReauthentication failed"},
	{	0, NULL }
};



/* 6.5.2.lB AKeyProtocolVersion
	N.S0011-0 v 1.0
 */
static const value_string ansi_map_AKeyProtocolVersion_vals[]  = {
    {   0, "Not used"},
    {   1, "A-key Generation not supported"},
    {   2, "Diffie Hellman with 768-bit modulus, 160-bit primitive, and 160-bit exponents"},
    {   3, "Diffie Hellman with 512-bit modulus, 160-bit primitive, and 160-bit exponents"},
    {   4, "Diffie Hellman with 768-bit modulus, 32-bit primitive, and 160-bit exponents"},
	{	0, NULL }
};
/* 6.5.2.sB OTASP_ResultCode
	N.S0011-0 v 1.0
 */
static const value_string ansi_map_OTASP_ResultCode_vals[]  = {
    {   0, "Accepted - Successful"},
    {   1, "Rejected - Unknown cause."},
    {   2, "Computation Failure - E.g., unable to compute A-key"},
    {   3, "CSC Rejected - CSC challenge failure"},
    {   4, "Unrecognized OTASPCallEntry"},
    {   5, "Unsupported AKeyProtocolVersion(s)"},
    {   6, "Unable to Commit"},
	{	0, NULL }
};

/*6.5.2.wB ServiceIndicator
	N.S0011-0 v 1.0
 */
static const value_string ansi_map_ServiceIndicator_vals[]  = {
    {   0, "Undefined Service"},
    {   1, "CDMA OTASP Service"},
    {   2, "TDMA OTASP Service"},
    {   3, "CDMA OTAPA Service"},
	{	0, NULL }
};

/* 6.5.2.xB SignalingMessageEncryptionReport
	N.S0011-0 v 1.0
 */
static const value_string ansi_map_SMEReport_vals[]  = {
    {   0, "Not used"},
    {   1, "Signaling Message Encryption enabling not attempted"},
    {   2, "Signaling Message Encryption enabling no response"},
    {   3, "Signaling Message Encryption is enabled"},
    {   4, "Signaling Message Encryption enabling failed"},
	{	0, NULL }
};

/* 6.5.2.zB VoicePrivacyReport
	N.S0011-0 v 1.0
 */
static const value_string ansi_map_VoicePrivacyReport_vals[]  = {
    {   0, "Not used"},
    {   1, "Voice Privacy not attempted"},
    {   2, "Voice Privacy no response"},
    {   3, "Voiec Privacy is active"},
    {   4, "Voice Privacy failed"},
	{	0, NULL }
};



/*--- Included file: packet-ansi_map-fn.c ---*/
#line 1 "packet-ansi_map-fn.c"
/*--- Fields for imported types ---*/

static int dissect_imsi_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_IMSI(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_imsi);
}



static int
dissect_ansi_map_OCTET_STRING_SIZE_0_2(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_componentIDs_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_OCTET_STRING_SIZE_0_2(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_componentIDs);
}



static int
dissect_ansi_map_INTEGER_M32768_32767(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_national_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_INTEGER_M32768_32767(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_national);
}
static int dissect_nationaler_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_INTEGER_M32768_32767(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_nationaler);
}



static int
dissect_ansi_map_PrivateOperationCode(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 85 "ansi_map.cnf"
   offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  &OperationCode);

 proto_tree_add_item(tree, hf_ansi_map_op_code_fam, tvb, offset-2,1,FALSE);
 proto_tree_add_item(tree, hf_ansi_map_op_code, tvb, offset-1,1,FALSE);



  return offset;
}
static int dissect_private_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_PrivateOperationCode(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_private);
}


static const value_string ansi_map_OperationCode_vals[] = {
  {  16, "national" },
  {  17, "private" },
  { 0, NULL }
};

static const ber_choice_t OperationCode_choice[] = {
  {  16, BER_CLASS_PRI, 16, BER_FLAGS_IMPLTAG, dissect_national_impl },
  {  17, BER_CLASS_PRI, 17, BER_FLAGS_IMPLTAG, dissect_private_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_ansi_map_OperationCode(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 OperationCode_choice, hf_index, ett_ansi_map_OperationCode,
                                 NULL);

  return offset;
}
static int dissect_operationCode(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_OperationCode(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_operationCode);
}



static int
dissect_ansi_map_InvokeParameters(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 23 "ansi_map.cnf"
  gint   *opcode;
  struct tcap_private_t *p_private_tcap;

  /* Data from the TCAP dissector */
  if (pinfo->private_data != NULL){
	  p_private_tcap=pinfo->private_data;
	  opcode = g_malloc(sizeof(gint));
	  OperationCode = OperationCode&0x00ff;
	  *opcode = OperationCode;
	  if ((!pinfo->fd->flags.visited)&&(p_private_tcap->TransactionID_str)){
		  /* Only do this once XXX I hope its the right thing to do */
		  g_hash_table_insert(TransactionId_table, g_strdup(p_private_tcap->TransactionID_str), opcode);
	  }	
  }
  ansi_map_is_invoke = TRUE;	
  if (check_col(pinfo->cinfo, COL_INFO)){
	  col_set_str(pinfo->cinfo, COL_INFO, val_to_str(OperationCode, ansi_map_opr_code_strings, "Unknown ANSI-MAP PDU (%u)"));
  }
  /* No Data */
  if(tvb_length_remaining(tvb, offset)<=0){
	  return offset;

  }

	offset = dissect_invokeData(pinfo, tree, tvb, offset);



  return offset;
}
static int dissect_invokeParameters_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_InvokeParameters(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_invokeParameters);
}


static const ber_sequence_t InvokePDU_sequence[] = {
  { BER_CLASS_PRI, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_componentIDs_impl },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_operationCode },
  { BER_CLASS_PRI, 18, BER_FLAGS_IMPLTAG, dissect_invokeParameters_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_InvokePDU(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   InvokePDU_sequence, hf_index, ett_ansi_map_InvokePDU);

  return offset;
}
static int dissect_invokeLast_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_InvokePDU(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_invokeLast);
}
static int dissect_invokeNotLast_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_InvokePDU(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_invokeNotLast);
}



static int
dissect_ansi_map_ComponentID(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_componentID(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_ComponentID(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_componentID);
}



static int
dissect_ansi_map_ReturnParameters(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 50 "ansi_map.cnf"
  gint   *opcode;
  struct tcap_private_t *p_private_tcap;
  proto_item *item;

  /* Data from the TCAP dissector */
  if (pinfo->private_data != NULL){
	  p_private_tcap=pinfo->private_data;
	  opcode = g_hash_table_lookup(TransactionId_table, p_private_tcap->TransactionID_str);
	  if(opcode){
		  OperationCode = *opcode;
	  }else{
		  OperationCode = OperationCode & 0x00ff;
	  }
  }else{
	  OperationCode = OperationCode & 0x00ff;
  }
  if (check_col(pinfo->cinfo, COL_INFO)){
	  col_clear(pinfo->cinfo, COL_INFO);
	  col_add_fstr(pinfo->cinfo, COL_INFO,"%s Response", val_to_str(OperationCode, ansi_map_opr_code_strings, "Unknown ANSI-MAP PDU (%u)"));
  }
  /* No Data */
  if(tvb_length_remaining(tvb, offset)<=0){
	  return offset;
  }

  item = proto_tree_add_text(tree, tvb, 0, -1, "OperationCode %s",val_to_str(OperationCode, ansi_map_opr_code_strings, "Unknown %u"));
  PROTO_ITEM_SET_GENERATED(item);

  offset = dissect_returnData(pinfo, tree, tvb, offset);



  return offset;
}
static int dissect_returnResult_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_ReturnParameters(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_returnResult);
}


static const ber_sequence_t ReturnResultPDU_sequence[] = {
  { BER_CLASS_PRI, 15, BER_FLAGS_NOOWNTAG, dissect_componentID },
  { BER_CLASS_PRI, 18, BER_FLAGS_IMPLTAG, dissect_returnResult_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_ReturnResultPDU(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ReturnResultPDU_sequence, hf_index, ett_ansi_map_ReturnResultPDU);

  return offset;
}
static int dissect_returnResultLast_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_ReturnResultPDU(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_returnResultLast);
}
static int dissect_returnResultNotLast_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_ReturnResultPDU(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_returnResultNotLast);
}



static int
dissect_ansi_map_INTEGER(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_privateer_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_INTEGER(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_privateer);
}


static const value_string ansi_map_ErrorCode_vals[] = {
  {  19, "nationaler" },
  {  20, "privateer" },
  { 0, NULL }
};

static const ber_choice_t ErrorCode_choice[] = {
  {  19, BER_CLASS_PRI, 19, BER_FLAGS_IMPLTAG, dissect_nationaler_impl },
  {  20, BER_CLASS_PRI, 20, BER_FLAGS_IMPLTAG, dissect_privateer_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_ansi_map_ErrorCode(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 ErrorCode_choice, hf_index, ett_ansi_map_ErrorCode,
                                 NULL);

  return offset;
}
static int dissect_errorCode(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_ErrorCode(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_errorCode);
}



static int
dissect_ansi_map_RejectParameters(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 83 "ansi_map.cnf"



  return offset;
}
static int dissect_parameterre(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_RejectParameters(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_parameterre);
}
static int dissect_parameterrj(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_RejectParameters(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_parameterrj);
}


static const ber_sequence_t ReturnErrorPDU_sequence[] = {
  { BER_CLASS_PRI, 15, BER_FLAGS_NOOWNTAG, dissect_componentID },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_errorCode },
  { BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_parameterre },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_ReturnErrorPDU(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ReturnErrorPDU_sequence, hf_index, ett_ansi_map_ReturnErrorPDU);

  return offset;
}
static int dissect_returnError_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_ReturnErrorPDU(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_returnError);
}


static const value_string ansi_map_ProblemPDU_vals[] = {
  { 257, "general-unrecognisedComponentType" },
  { 258, "general-incorrectComponentPortion" },
  { 259, "general-badlyStructuredCompPortion" },
  { 0, NULL }
};


static int
dissect_ansi_map_ProblemPDU(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_rejectProblem_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_ProblemPDU(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_rejectProblem);
}


static const ber_sequence_t RejectPDU_sequence[] = {
  { BER_CLASS_PRI, 15, BER_FLAGS_NOOWNTAG, dissect_componentID },
  { BER_CLASS_PRI, 21, BER_FLAGS_IMPLTAG, dissect_rejectProblem_impl },
  { BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_parameterrj },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_RejectPDU(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   RejectPDU_sequence, hf_index, ett_ansi_map_RejectPDU);

  return offset;
}
static int dissect_reject_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_RejectPDU(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_reject);
}


static const value_string ansi_map_ComponentPDU_vals[] = {
  {   9, "invokeLast" },
  {  10, "returnResultLast" },
  {  11, "returnError" },
  {  12, "reject" },
  {  13, "invokeNotLast" },
  {  14, "returnResultNotLast" },
  { 0, NULL }
};

static const ber_choice_t ComponentPDU_choice[] = {
  {   9, BER_CLASS_PRI, 9, BER_FLAGS_IMPLTAG, dissect_invokeLast_impl },
  {  10, BER_CLASS_PRI, 10, BER_FLAGS_IMPLTAG, dissect_returnResultLast_impl },
  {  11, BER_CLASS_PRI, 11, BER_FLAGS_IMPLTAG, dissect_returnError_impl },
  {  12, BER_CLASS_PRI, 12, BER_FLAGS_IMPLTAG, dissect_reject_impl },
  {  13, BER_CLASS_PRI, 13, BER_FLAGS_IMPLTAG, dissect_invokeNotLast_impl },
  {  14, BER_CLASS_PRI, 14, BER_FLAGS_IMPLTAG, dissect_returnResultNotLast_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_ansi_map_ComponentPDU(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 ComponentPDU_choice, hf_index, ett_ansi_map_ComponentPDU,
                                 NULL);

  return offset;
}



static int
dissect_ansi_map_ErrorParameters(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 81 "ansi_map.cnf"



  return offset;
}



static int
dissect_ansi_map_ElectronicSerialNumber(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_electronicSerialNumber_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_ElectronicSerialNumber(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_electronicSerialNumber);
}
static int dissect_lectronicSerialNumber_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_ElectronicSerialNumber(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_lectronicSerialNumber);
}



static int
dissect_ansi_map_MINType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 90 "ansi_map.cnf"
	tvbuff_t *parameter_tvb = NULL;
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       &parameter_tvb);

	if (parameter_tvb){
		dissect_ansi_map_min_type(parameter_tvb,pinfo,tree);
	}



  return offset;
}



static int
dissect_ansi_map_MobileIdentificationNumber(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ansi_map_MINType(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_mobileIdentificationNumber_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_MobileIdentificationNumber(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_mobileIdentificationNumber);
}


static const value_string ansi_map_MSID_vals[] = {
  {   8, "mobileIdentificationNumber" },
  { 242, "imsi" },
  { 0, NULL }
};

static const ber_choice_t MSID_choice[] = {
  {   8, BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_mobileIdentificationNumber_impl },
  { 242, BER_CLASS_CON, 242, BER_FLAGS_IMPLTAG, dissect_imsi_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_ansi_map_MSID(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 MSID_choice, hf_index, ett_ansi_map_MSID,
                                 NULL);

  return offset;
}
static int dissect_msid(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_MSID(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_msid);
}



static int
dissect_ansi_map_AuthenticationAlgorithmVersion(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_authenticationAlgorithmVersion_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_AuthenticationAlgorithmVersion(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_authenticationAlgorithmVersion);
}



static int
dissect_ansi_map_AuthenticationResponseReauthentication(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_authenticationResponseReauthentication_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_AuthenticationResponseReauthentication(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_authenticationResponseReauthentication);
}



static int
dissect_ansi_map_AuthenticationResponseUniqueChallenge(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_authenticationResponseUniqueChallenge_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_AuthenticationResponseUniqueChallenge(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_authenticationResponseUniqueChallenge);
}



static int
dissect_ansi_map_CallHistoryCount(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_callHistoryCount_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_CallHistoryCount(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_callHistoryCount);
}



static int
dissect_ansi_map_CDMAPrivateLongCodeMask(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_cdmaPrivateLongCodeMask_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_CDMAPrivateLongCodeMask(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_cdmaPrivateLongCodeMask);
}



static int
dissect_ansi_map_DigitsType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 97 "ansi_map.cnf"
	tvbuff_t *parameter_tvb = NULL;
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       &parameter_tvb);

	if (parameter_tvb){
		dissect_ansi_map_digits_type(parameter_tvb,pinfo,tree);
	}



  return offset;
}



static int
dissect_ansi_map_CarrierDigits(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ansi_map_DigitsType(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_carrierDigits_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_CarrierDigits(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_carrierDigits);
}


static const value_string ansi_map_DenyAccess_vals[] = {
  {   0, "not-used" },
  {   1, "unspecified" },
  {   2, "ssd-Update-failure" },
  {   3, "cOUNT-Update-failure" },
  {   4, "unique-Challenge-failure" },
  {   5, "aUTHR-mismatch" },
  {   6, "cOUNT-mismatch" },
  {   7, "process-collision" },
  {   8, "missing-authentication-parameters" },
  {   9, "terminalType-mismatch" },
  {  10, "mIN-IMSI-or-ESN-authorization-failure" },
  { 0, NULL }
};


static int
dissect_ansi_map_DenyAccess(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_denyAccess_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_DenyAccess(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_denyAccess);
}



static int
dissect_ansi_map_DestinationDigits(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ansi_map_DigitsType(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_destinationDigits_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_DestinationDigits(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_destinationDigits);
}



static int
dissect_ansi_map_LocationAreaID(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_locationAreaID_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_LocationAreaID(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_locationAreaID);
}



static int
dissect_ansi_map_RandomVariableReauthentication(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_randomVariableReauthentication_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_RandomVariableReauthentication(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_randomVariableReauthentication);
}



static int
dissect_ansi_map_MobileStationMIN(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ansi_map_MINType(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_mobileStationMIN_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_MobileStationMIN(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_mobileStationMIN);
}



static int
dissect_ansi_map_MSCID(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 247 "ansi_map.cnf"
	tvbuff_t *parameter_tvb = NULL;
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       &parameter_tvb);

	if (parameter_tvb){
		dissect_ansi_map_mscid(parameter_tvb,pinfo,tree);
	}



  return offset;
}
static int dissect_mscid_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_MSCID(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_mscid);
}



static int
dissect_ansi_map_RandomVariableSSD(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_randomVariableSSD_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_RandomVariableSSD(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_randomVariableSSD);
}



static int
dissect_ansi_map_RandomVariableUniqueChallenge(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_randomVariableUniqueChallenge_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_RandomVariableUniqueChallenge(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_randomVariableUniqueChallenge);
}



static int
dissect_ansi_map_RoutingDigits(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ansi_map_DigitsType(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_routingDigits_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_RoutingDigits(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_routingDigits);
}
static int dissect_outingDigits_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_RoutingDigits(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_outingDigits);
}



static int
dissect_ansi_map_SenderIdentificationNumber(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ansi_map_DigitsType(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_senderIdentificationNumber_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_SenderIdentificationNumber(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_senderIdentificationNumber);
}



static int
dissect_ansi_map_SharedSecretData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_sharedSecretData_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_SharedSecretData(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_sharedSecretData);
}



static int
dissect_ansi_map_SignalingMessageEncryptionKey(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_signalingMessageEncryptionKey_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_SignalingMessageEncryptionKey(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_signalingMessageEncryptionKey);
}


static const value_string ansi_map_SSDNotShared_vals[] = {
  {   0, "not-used" },
  {   1, "discard-SSD" },
  { 0, NULL }
};


static int
dissect_ansi_map_SSDNotShared(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_ssdnotShared_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_SSDNotShared(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_ssdnotShared);
}


static const value_string ansi_map_UpdateCount_vals[] = {
  {   0, "not-used" },
  {   1, "update-COUNT" },
  { 0, NULL }
};


static int
dissect_ansi_map_UpdateCount(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_updateCount_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_UpdateCount(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_updateCount);
}


static const ber_sequence_t AuthenticationDirective_set[] = {
  { BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_electronicSerialNumber_impl },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_msid },
  { BER_CLASS_CON, 77, BER_FLAGS_IMPLTAG, dissect_authenticationAlgorithmVersion_impl },
  { BER_CLASS_CON, 182, BER_FLAGS_IMPLTAG, dissect_authenticationResponseReauthentication_impl },
  { BER_CLASS_CON, 37, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_authenticationResponseUniqueChallenge_impl },
  { BER_CLASS_CON, 38, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callHistoryCount_impl },
  { BER_CLASS_CON, 67, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaPrivateLongCodeMask_impl },
  { BER_CLASS_CON, 86, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_carrierDigits_impl },
  { BER_CLASS_CON, 50, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_denyAccess_impl },
  { BER_CLASS_CON, 87, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_destinationDigits_impl },
  { BER_CLASS_CON, 33, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_locationAreaID_impl },
  { BER_CLASS_CON, 191, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_randomVariableReauthentication_impl },
  { BER_CLASS_CON, 184, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mobileStationMIN_impl },
  { BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mscid_impl },
  { BER_CLASS_CON, 42, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_randomVariableSSD_impl },
  { BER_CLASS_CON, 43, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_randomVariableUniqueChallenge_impl },
  { BER_CLASS_CON, 150, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_routingDigits_impl },
  { BER_CLASS_CON, 103, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_senderIdentificationNumber_impl },
  { BER_CLASS_CON, 46, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sharedSecretData_impl },
  { BER_CLASS_CON, 45, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_signalingMessageEncryptionKey_impl },
  { BER_CLASS_CON, 52, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ssdnotShared_impl },
  { BER_CLASS_CON, 51, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_updateCount_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_AuthenticationDirective(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              AuthenticationDirective_set, hf_index, ett_ansi_map_AuthenticationDirective);

  return offset;
}
static int dissect_authenticationDirective(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_AuthenticationDirective(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_authenticationDirective);
}


static const ber_sequence_t AuthenticationDirectiveRes_set[] = {
  { BER_CLASS_CON, 38, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callHistoryCount_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_AuthenticationDirectiveRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              AuthenticationDirectiveRes_set, hf_index, ett_ansi_map_AuthenticationDirectiveRes);

  return offset;
}
static int dissect_authenticationDirectiveRes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_AuthenticationDirectiveRes(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_authenticationDirectiveRes);
}



static int
dissect_ansi_map_InterMSCCircuitID(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 222 "ansi_map.cnf"
	tvbuff_t *parameter_tvb = NULL;
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       &parameter_tvb);

	if (parameter_tvb){
		dissect_ansi_map_intermsccircuitid(parameter_tvb,pinfo,tree);
	}



  return offset;
}
static int dissect_interMSCCircuitID_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_InterMSCCircuitID(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_interMSCCircuitID);
}


static const ber_sequence_t AuthenticationDirectiveForward_set[] = {
  { BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_interMSCCircuitID_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_mobileIdentificationNumber_impl },
  { BER_CLASS_CON, 37, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_authenticationResponseUniqueChallenge_impl },
  { BER_CLASS_CON, 43, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_randomVariableUniqueChallenge_impl },
  { BER_CLASS_CON, 51, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_updateCount_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_AuthenticationDirectiveForward(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              AuthenticationDirectiveForward_set, hf_index, ett_ansi_map_AuthenticationDirectiveForward);

  return offset;
}
static int dissect_authenticationDirectiveForward(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_AuthenticationDirectiveForward(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_authenticationDirectiveForward);
}



static int
dissect_ansi_map_CountUpdateReport(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_countUpdateReport_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_CountUpdateReport(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_countUpdateReport);
}



static int
dissect_ansi_map_UniqueChallengeReport(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_uniqueChallengeReport_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_UniqueChallengeReport(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_uniqueChallengeReport);
}


static const ber_sequence_t AuthenticationDirectiveForwardRes_set[] = {
  { BER_CLASS_CON, 138, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_countUpdateReport_impl },
  { BER_CLASS_CON, 124, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_uniqueChallengeReport_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_AuthenticationDirectiveForwardRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              AuthenticationDirectiveForwardRes_set, hf_index, ett_ansi_map_AuthenticationDirectiveForwardRes);

  return offset;
}
static int dissect_authenticationDirectiveForwardRes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_AuthenticationDirectiveForwardRes(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_authenticationDirectiveForwardRes);
}


static const value_string ansi_map_ReportType_vals[] = {
  {   0, "not-used" },
  {   1, "unspecified-security-violation" },
  {   2, "mSID-ESN-mismatch" },
  {   3, "rANDC-mismatch" },
  {   4, "reserved" },
  {   5, "sSD-update-failed" },
  {   6, "reserved" },
  {   7, "cOUNT-mismatch" },
  {   8, "reserved" },
  {   9, "unique-Challenge-failed" },
  {  10, "unsolicited-Base-Station-Challenge" },
  {  11, "sSD-Update-no-response" },
  {  12, "cOUNT-Update-no-response" },
  {  13, "unique-Challenge-no-response" },
  {  14, "aUTHR-mismatch" },
  {  15, "tERMTYP-mismatch" },
  {  16, "missing-authentication-parameters" },
  { 0, NULL }
};


static int
dissect_ansi_map_ReportType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_reportType_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_ReportType(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_reportType);
}
static int dissect_reportType2_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_ReportType(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_reportType2);
}


static const value_string ansi_map_SystemAccessType_vals[] = {
  {   0, "not-used" },
  {   1, "unspecified" },
  {   2, "flash-request" },
  {   3, "autonomous-registration" },
  {   4, "call-origination" },
  {   5, "page-response" },
  {   6, "no-access" },
  {   7, "power-down-registration" },
  {   8, "sms-page-response" },
  {   9, "otasp" },
  { 0, NULL }
};


static int
dissect_ansi_map_SystemAccessType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_systemAccessType_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_SystemAccessType(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_systemAccessType);
}



static int
dissect_ansi_map_SystemCapabilities(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 368 "ansi_map.cnf"
	tvbuff_t *parameter_tvb = NULL;
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       &parameter_tvb);

	if (parameter_tvb){
		dissect_ansi_map_systemcapabilities(parameter_tvb,pinfo,tree);
	}




  return offset;
}
static int dissect_systemCapabilities_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_SystemCapabilities(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_systemCapabilities);
}



static int
dissect_ansi_map_CallHistoryCountExpected(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_callHistoryCountExpected_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_CallHistoryCountExpected(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_callHistoryCountExpected);
}


static const value_string ansi_map_TerminalType_vals[] = {
  {   0, "not-used" },
  {   1, "not-distinguished" },
  {   2, "iS-54-B" },
  {   3, "iS-136" },
  {   4, "j-STD-011" },
  {   5, "iS-136-A-or-TIA-EIA-136-Revision-0" },
  {   6, "tIA-EIA-136-A" },
  {   7, "iA-EIA-136-B" },
  {  32, "iS-95" },
  {  33, "iS-95B" },
  {  34, "j-STD-008" },
  {  35, "tIA-EIA-95-B" },
  {  36, "iS-2000" },
  {  64, "iS-88" },
  {  65, "iS-94" },
  {  66, "iS-91" },
  {  67, "j-STD-014" },
  {  68, "tIA-EIA-553-A" },
  {  69, "iS-91-A" },
  { 0, NULL }
};


static int
dissect_ansi_map_TerminalType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_terminalType_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_TerminalType(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_terminalType);
}


static const ber_sequence_t AuthenticationFailureReport_set[] = {
  { BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_electronicSerialNumber_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_mobileIdentificationNumber_impl },
  { BER_CLASS_CON, 44, BER_FLAGS_IMPLTAG, dissect_reportType_impl },
  { BER_CLASS_CON, 34, BER_FLAGS_IMPLTAG, dissect_systemAccessType_impl },
  { BER_CLASS_CON, 49, BER_FLAGS_IMPLTAG, dissect_systemCapabilities_impl },
  { BER_CLASS_CON, 38, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callHistoryCount_impl },
  { BER_CLASS_CON, 79, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callHistoryCountExpected_impl },
  { BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mscid_impl },
  { BER_CLASS_CON, 44, BER_FLAGS_IMPLTAG, dissect_reportType2_impl },
  { BER_CLASS_CON, 103, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_senderIdentificationNumber_impl },
  { BER_CLASS_CON, 47, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_terminalType_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_AuthenticationFailureReport(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              AuthenticationFailureReport_set, hf_index, ett_ansi_map_AuthenticationFailureReport);

  return offset;
}
static int dissect_authenticationFailureReport(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_AuthenticationFailureReport(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_authenticationFailureReport);
}


static const ber_sequence_t AuthenticationFailureReportRes_set[] = {
  { BER_CLASS_CON, 77, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_authenticationAlgorithmVersion_impl },
  { BER_CLASS_CON, 37, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_authenticationResponseUniqueChallenge_impl },
  { BER_CLASS_CON, 38, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callHistoryCount_impl },
  { BER_CLASS_CON, 86, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_carrierDigits_impl },
  { BER_CLASS_CON, 50, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_denyAccess_impl },
  { BER_CLASS_CON, 87, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_destinationDigits_impl },
  { BER_CLASS_CON, 42, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_randomVariableSSD_impl },
  { BER_CLASS_CON, 43, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_randomVariableUniqueChallenge_impl },
  { BER_CLASS_CON, 46, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sharedSecretData_impl },
  { BER_CLASS_CON, 150, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_routingDigits_impl },
  { BER_CLASS_CON, 52, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ssdnotShared_impl },
  { BER_CLASS_CON, 47, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_terminalType_impl },
  { BER_CLASS_CON, 51, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_updateCount_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_AuthenticationFailureReportRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              AuthenticationFailureReportRes_set, hf_index, ett_ansi_map_AuthenticationFailureReportRes);

  return offset;
}
static int dissect_authenticationFailureReportRes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_AuthenticationFailureReportRes(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_authenticationFailureReportRes);
}



static int
dissect_ansi_map_AuthenticationData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_authenticationData_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_AuthenticationData(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_authenticationData);
}



static int
dissect_ansi_map_AuthenticationResponse(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_authenticationResponse_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_AuthenticationResponse(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_authenticationResponse);
}



static int
dissect_ansi_map_CDMANetworkIdentification(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_cdmaNetworkIdentification_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_CDMANetworkIdentification(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_cdmaNetworkIdentification);
}



static int
dissect_ansi_map_ConfidentialityModes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 183 "ansi_map.cnf"
	tvbuff_t *parameter_tvb = NULL;
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       &parameter_tvb);

	if (parameter_tvb){
		dissect_ansi_map_confidentialitymodes(parameter_tvb,pinfo,tree);
	}



  return offset;
}
static int dissect_confidentialityModes_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_ConfidentialityModes(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_confidentialityModes);
}



static int
dissect_ansi_map_ControlChannelMode(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_controlChannelMode_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_ControlChannelMode(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_controlChannelMode);
}



static int
dissect_ansi_map_Digits(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ansi_map_DigitsType(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_digits_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_Digits(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_digits);
}
static int dissect_digits_Destination_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_Digits(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_digits_Destination);
}
static int dissect_digits_carrier_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_Digits(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_digits_carrier);
}
static int dissect_digits_dest_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_Digits(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_digits_dest);
}
static int dissect_digits_Carrier_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_Digits(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_digits_Carrier);
}



static int
dissect_ansi_map_PC_SSN(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 303 "ansi_map.cnf"
	tvbuff_t *parameter_tvb = NULL;
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       &parameter_tvb);

	if (parameter_tvb){
		dissect_ansi_map_pc_ssn(parameter_tvb,pinfo,tree);
	}



  return offset;
}
static int dissect_pc_ssn_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_PC_SSN(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_pc_ssn);
}
static int dissect_pC_SSN_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_PC_SSN(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_pC_SSN);
}



static int
dissect_ansi_map_RandomVariable(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_randomVariable_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_RandomVariable(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_randomVariable);
}



static int
dissect_ansi_map_ServiceRedirectionCause(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_serviceRedirectionCause_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_ServiceRedirectionCause(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_serviceRedirectionCause);
}


static const value_string ansi_map_SuspiciousAccess_vals[] = {
  {   0, "not-used" },
  {   1, "anomalous-Digits" },
  {   2, "unspecified" },
  { 0, NULL }
};


static int
dissect_ansi_map_SuspiciousAccess(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_suspiciousAccess_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_SuspiciousAccess(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_suspiciousAccess);
}



static int
dissect_ansi_map_TransactionCapability(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 385 "ansi_map.cnf"
	tvbuff_t *parameter_tvb = NULL;
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       &parameter_tvb);

	if (parameter_tvb){
		dissect_ansi_map_transactioncapability(parameter_tvb,pinfo,tree);
	}



  return offset;
}
static int dissect_transactionCapability_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_TransactionCapability(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_transactionCapability);
}


static const ber_sequence_t AuthenticationRequest_set[] = {
  { BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_electronicSerialNumber_impl },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_msid },
  { BER_CLASS_CON, 21, BER_FLAGS_IMPLTAG, dissect_mscid_impl },
  { BER_CLASS_CON, 34, BER_FLAGS_IMPLTAG, dissect_systemAccessType_impl },
  { BER_CLASS_CON, 49, BER_FLAGS_IMPLTAG, dissect_systemCapabilities_impl },
  { BER_CLASS_CON, 161, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_authenticationData_impl },
  { BER_CLASS_CON, 35, BER_FLAGS_IMPLTAG, dissect_authenticationResponse_impl },
  { BER_CLASS_CON, 38, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callHistoryCount_impl },
  { BER_CLASS_CON, 232, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaNetworkIdentification_impl },
  { BER_CLASS_CON, 39, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_confidentialityModes_impl },
  { BER_CLASS_CON, 199, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_controlChannelMode_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_digits_impl },
  { BER_CLASS_CON, 32, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pc_ssn_impl },
  { BER_CLASS_CON, 40, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_randomVariable_impl },
  { BER_CLASS_CON, 237, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_serviceRedirectionCause_impl },
  { BER_CLASS_CON, 103, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_senderIdentificationNumber_impl },
  { BER_CLASS_CON, 285, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_suspiciousAccess_impl },
  { BER_CLASS_CON, 47, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_terminalType_impl },
  { BER_CLASS_CON, 123, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_transactionCapability_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_AuthenticationRequest(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              AuthenticationRequest_set, hf_index, ett_ansi_map_AuthenticationRequest);

  return offset;
}
static int dissect_authenticationRequest(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_AuthenticationRequest(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_authenticationRequest);
}



static int
dissect_ansi_map_AnalogRedirectInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_analogRedirectInfo_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_AnalogRedirectInfo(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_analogRedirectInfo);
}


static const ber_sequence_t AnalogRedirectRecord_sequence[] = {
  { BER_CLASS_CON, 224, BER_FLAGS_IMPLTAG, dissect_analogRedirectInfo_impl },
  { BER_CLASS_CON, 21, BER_FLAGS_IMPLTAG, dissect_mscid_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_AnalogRedirectRecord(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   AnalogRedirectRecord_sequence, hf_index, ett_ansi_map_AnalogRedirectRecord);

  return offset;
}
static int dissect_analogRedirectRecord_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_AnalogRedirectRecord(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_analogRedirectRecord);
}



static int
dissect_ansi_map_CDMABandClass(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_cdmaBandClass_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_CDMABandClass(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_cdmaBandClass);
}



static int
dissect_ansi_map_CDMAChannelNumber(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_cdmaChannelNumber_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_CDMAChannelNumber(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_cdmaChannelNumber);
}
static int dissect_cdmaChannelNumber2_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_CDMAChannelNumber(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_cdmaChannelNumber2);
}


static const ber_sequence_t CDMAChannelNumberList_item_sequence[] = {
  { BER_CLASS_CON, 226, BER_FLAGS_IMPLTAG, dissect_cdmaChannelNumber_impl },
  { BER_CLASS_CON, 226, BER_FLAGS_IMPLTAG, dissect_cdmaChannelNumber2_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_CDMAChannelNumberList_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   CDMAChannelNumberList_item_sequence, hf_index, ett_ansi_map_CDMAChannelNumberList_item);

  return offset;
}
static int dissect_CDMAChannelNumberList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_CDMAChannelNumberList_item(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_CDMAChannelNumberList_item);
}


static const ber_sequence_t CDMAChannelNumberList_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_CDMAChannelNumberList_item },
};

static int
dissect_ansi_map_CDMAChannelNumberList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      CDMAChannelNumberList_sequence_of, hf_index, ett_ansi_map_CDMAChannelNumberList);

  return offset;
}
static int dissect_cdmaChannelNumberList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_CDMAChannelNumberList(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_cdmaChannelNumberList);
}


static const ber_sequence_t CDMARedirectRecord_sequence[] = {
  { BER_CLASS_CON, 170, BER_FLAGS_IMPLTAG, dissect_cdmaBandClass_impl },
  { BER_CLASS_CON, 227, BER_FLAGS_IMPLTAG, dissect_cdmaChannelNumberList_impl },
  { BER_CLASS_CON, 21, BER_FLAGS_IMPLTAG, dissect_mscid_impl },
  { BER_CLASS_CON, 232, BER_FLAGS_IMPLTAG, dissect_cdmaNetworkIdentification_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_CDMARedirectRecord(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   CDMARedirectRecord_sequence, hf_index, ett_ansi_map_CDMARedirectRecord);

  return offset;
}
static int dissect_cdmaRedirectRecord_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_CDMARedirectRecord(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_cdmaRedirectRecord);
}



static int
dissect_ansi_map_DataKey(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_dataKey_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_DataKey(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_dataKey);
}



static int
dissect_ansi_map_RoamingIndication(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_roamingIndication_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_RoamingIndication(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_roamingIndication);
}



static int
dissect_ansi_map_ServiceRedirectionInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_serviceRedirectionInfo_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_ServiceRedirectionInfo(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_serviceRedirectionInfo);
}



static int
dissect_ansi_map_VoicePrivacyMask(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_voicePrivacyMask_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_VoicePrivacyMask(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_voicePrivacyMask);
}


static const ber_sequence_t AuthenticationRequestRes_set[] = {
  { BER_CLASS_CON, 225, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_analogRedirectRecord_impl },
  { BER_CLASS_CON, 77, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_authenticationAlgorithmVersion_impl },
  { BER_CLASS_CON, 37, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_authenticationResponseUniqueChallenge_impl },
  { BER_CLASS_CON, 38, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callHistoryCount_impl },
  { BER_CLASS_CON, 86, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_carrierDigits_impl },
  { BER_CLASS_CON, 67, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaPrivateLongCodeMask_impl },
  { BER_CLASS_CON, 229, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaRedirectRecord_impl },
  { BER_CLASS_CON, 215, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dataKey_impl },
  { BER_CLASS_CON, 50, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_denyAccess_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mobileIdentificationNumber_impl },
  { BER_CLASS_CON, 239, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_roamingIndication_impl },
  { BER_CLASS_CON, 238, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_serviceRedirectionInfo_impl },
  { BER_CLASS_CON, 87, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_destinationDigits_impl },
  { BER_CLASS_CON, 42, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_randomVariableSSD_impl },
  { BER_CLASS_CON, 43, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_randomVariableUniqueChallenge_impl },
  { BER_CLASS_CON, 150, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_routingDigits_impl },
  { BER_CLASS_CON, 46, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sharedSecretData_impl },
  { BER_CLASS_CON, 45, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_signalingMessageEncryptionKey_impl },
  { BER_CLASS_CON, 52, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ssdnotShared_impl },
  { BER_CLASS_CON, 51, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_updateCount_impl },
  { BER_CLASS_CON, 48, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_voicePrivacyMask_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_AuthenticationRequestRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              AuthenticationRequestRes_set, hf_index, ett_ansi_map_AuthenticationRequestRes);

  return offset;
}
static int dissect_authenticationRequestRes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_AuthenticationRequestRes(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_authenticationRequestRes);
}



static int
dissect_ansi_map_ReauthenticationReport(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_reauthenticationReport_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_ReauthenticationReport(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_reauthenticationReport);
}



static int
dissect_ansi_map_ServiceIndicator(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 462 "ansi_map.cnf"
	tvbuff_t *parameter_tvb = NULL;
	guint8 ServiceIndicator;
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       &parameter_tvb);

	if (parameter_tvb){
		if (SMS_BearerData_tvb !=NULL)
		{
			ServiceIndicator = tvb_get_guint8(parameter_tvb,0);
			switch(ServiceIndicator){
				case 1: /* CDMA OTASP Service */
				case 3: /* CDMA OTAPA Service */
					dissector_try_port(is683_dissector_table, ansi_map_is_invoke ? 0 : 1, SMS_BearerData_tvb, g_pinfo, g_tree);
					break;
				case 4: /* CDMA Position Determination Service */
					dissector_try_port(is801_dissector_table, ansi_map_is_invoke ? 0 : 1, SMS_BearerData_tvb, g_pinfo, g_tree);
					break;
				default:
					break;
			}
		}
	}
	 


  return offset;
}
static int dissect_serviceIndicator_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_ServiceIndicator(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_serviceIndicator);
}



static int
dissect_ansi_map_SignalingMessageEncryptionReport(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_signalingMessageEncryptionReport_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_SignalingMessageEncryptionReport(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_signalingMessageEncryptionReport);
}



static int
dissect_ansi_map_SSDUpdateReport(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_ssdUpdateReport_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_SSDUpdateReport(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_ssdUpdateReport);
}



static int
dissect_ansi_map_VoicePrivacyReport(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_voicePrivacyReport_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_VoicePrivacyReport(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_voicePrivacyReport);
}


static const ber_sequence_t AuthenticationStatusReport_set[] = {
  { BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_electronicSerialNumber_impl },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_msid },
  { BER_CLASS_CON, 49, BER_FLAGS_IMPLTAG, dissect_systemCapabilities_impl },
  { BER_CLASS_CON, 138, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_countUpdateReport_impl },
  { BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mscid_impl },
  { BER_CLASS_CON, 192, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_reauthenticationReport_impl },
  { BER_CLASS_CON, 103, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_senderIdentificationNumber_impl },
  { BER_CLASS_CON, 193, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_serviceIndicator_impl },
  { BER_CLASS_CON, 194, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_signalingMessageEncryptionReport_impl },
  { BER_CLASS_CON, 156, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ssdUpdateReport_impl },
  { BER_CLASS_CON, 124, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_uniqueChallengeReport_impl },
  { BER_CLASS_CON, 196, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_voicePrivacyReport_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_AuthenticationStatusReport(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              AuthenticationStatusReport_set, hf_index, ett_ansi_map_AuthenticationStatusReport);

  return offset;
}
static int dissect_authenticationStatusReport(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_AuthenticationStatusReport(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_authenticationStatusReport);
}


static const ber_sequence_t AuthenticationStatusReportRes_set[] = {
  { BER_CLASS_CON, 77, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_authenticationAlgorithmVersion_impl },
  { BER_CLASS_CON, 37, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_authenticationResponseUniqueChallenge_impl },
  { BER_CLASS_CON, 38, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callHistoryCount_impl },
  { BER_CLASS_CON, 86, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_carrierDigits_impl },
  { BER_CLASS_CON, 50, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_denyAccess_impl },
  { BER_CLASS_CON, 87, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_destinationDigits_impl },
  { BER_CLASS_CON, 42, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_randomVariableSSD_impl },
  { BER_CLASS_CON, 43, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_randomVariableUniqueChallenge_impl },
  { BER_CLASS_CON, 150, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_routingDigits_impl },
  { BER_CLASS_CON, 46, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sharedSecretData_impl },
  { BER_CLASS_CON, 52, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ssdnotShared_impl },
  { BER_CLASS_CON, 51, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_updateCount_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_AuthenticationStatusReportRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              AuthenticationStatusReportRes_set, hf_index, ett_ansi_map_AuthenticationStatusReportRes);

  return offset;
}
static int dissect_authenticationStatusReportRes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_AuthenticationStatusReportRes(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_authenticationStatusReportRes);
}



static int
dissect_ansi_map_RandomVariableBaseStation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_randomVariableBaseStation_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_RandomVariableBaseStation(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_randomVariableBaseStation);
}


static const ber_sequence_t BaseStationChallenge_set[] = {
  { BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_electronicSerialNumber_impl },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_msid },
  { BER_CLASS_CON, 41, BER_FLAGS_IMPLTAG, dissect_randomVariableBaseStation_impl },
  { BER_CLASS_CON, 103, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_senderIdentificationNumber_impl },
  { BER_CLASS_CON, 193, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_serviceIndicator_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_BaseStationChallenge(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              BaseStationChallenge_set, hf_index, ett_ansi_map_BaseStationChallenge);

  return offset;
}
static int dissect_baseStationChallenge(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_BaseStationChallenge(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_baseStationChallenge);
}



static int
dissect_ansi_map_AuthenticationResponseBaseStation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_authenticationResponseBaseStation_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_AuthenticationResponseBaseStation(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_authenticationResponseBaseStation);
}


static const ber_sequence_t BaseStationChallengeRes_set[] = {
  { BER_CLASS_CON, 36, BER_FLAGS_IMPLTAG, dissect_authenticationResponseBaseStation_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_BaseStationChallengeRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              BaseStationChallengeRes_set, hf_index, ett_ansi_map_BaseStationChallengeRes);

  return offset;
}


static const ber_sequence_t Blocking_set[] = {
  { BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_interMSCCircuitID_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_Blocking(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              Blocking_set, hf_index, ett_ansi_map_Blocking);

  return offset;
}
static int dissect_blocking(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_Blocking(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_blocking);
}


static const ber_sequence_t BulkDeregistration_set[] = {
  { BER_CLASS_CON, 103, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_senderIdentificationNumber_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_BulkDeregistration(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              BulkDeregistration_set, hf_index, ett_ansi_map_BulkDeregistration);

  return offset;
}
static int dissect_bulkDeregistration(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_BulkDeregistration(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_bulkDeregistration);
}


static const ber_sequence_t CountRequest_set[] = {
  { BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_electronicSerialNumber_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_mobileIdentificationNumber_impl },
  { BER_CLASS_CON, 103, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_senderIdentificationNumber_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_CountRequest(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              CountRequest_set, hf_index, ett_ansi_map_CountRequest);

  return offset;
}
static int dissect_countRequest(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_CountRequest(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_countRequest);
}


static const ber_sequence_t CountRequestRes_set[] = {
  { BER_CLASS_CON, 38, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callHistoryCount_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_CountRequestRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              CountRequestRes_set, hf_index, ett_ansi_map_CountRequestRes);

  return offset;
}
static int dissect_countRequestRes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_CountRequestRes(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_countRequestRes);
}



static int
dissect_ansi_map_BillingID(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 137 "ansi_map.cnf"
	tvbuff_t *parameter_tvb = NULL;
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       &parameter_tvb);

	if (parameter_tvb){
		dissect_ansi_map_billingid(parameter_tvb,pinfo,tree);
	}



  return offset;
}
static int dissect_billingID_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_BillingID(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_billingID);
}



static int
dissect_ansi_map_ChannelData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 175 "ansi_map.cnf"
	tvbuff_t *parameter_tvb = NULL;
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       &parameter_tvb);

	if (parameter_tvb){
		dissect_ansi_map_channeldata(parameter_tvb,pinfo,tree);
	}



  return offset;
}
static int dissect_channelData_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_ChannelData(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_channelData);
}



static int
dissect_ansi_map_InterSwitchCount(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_interSwitchCount_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_InterSwitchCount(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_interSwitchCount);
}



static int
dissect_ansi_map_ServingCellID(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_servingCellID_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_ServingCellID(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_servingCellID);
}



static int
dissect_ansi_map_StationClassMark(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_stationClassMark_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_StationClassMark(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_stationClassMark);
}



static int
dissect_ansi_map_TargetCellID(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_targetCellID_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_TargetCellID(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_targetCellID);
}
static int dissect_targetCellID1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_TargetCellID(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_targetCellID1);
}


static const value_string ansi_map_HandoffReason_vals[] = {
  {   0, "not-used" },
  {   1, "unspecified" },
  {   2, "weak-Signal" },
  {   3, "off-loading" },
  {   4, "anticipatory" },
  { 0, NULL }
};


static int
dissect_ansi_map_HandoffReason(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_handoffReason_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_HandoffReason(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_handoffReason);
}



static int
dissect_ansi_map_HandoffState(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 214 "ansi_map.cnf"
	tvbuff_t *parameter_tvb = NULL;
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       &parameter_tvb);

	if (parameter_tvb){
		dissect_ansi_map_handoffstate(parameter_tvb,pinfo,tree);
	}



  return offset;
}
static int dissect_handoffState_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_HandoffState(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_handoffState);
}



static int
dissect_ansi_map_TDMABurstIndicator(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_tdmaBurstIndicator_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_TDMABurstIndicator(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_tdmaBurstIndicator);
}



static int
dissect_ansi_map_TDMACallMode(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_tdmaCallMode_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_TDMACallMode(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_tdmaCallMode);
}



static int
dissect_ansi_map_TDMAChannelData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_tdmaChannelData_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_TDMAChannelData(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_tdmaChannelData);
}


static const ber_sequence_t FacilitiesDirective_set[] = {
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_billingID_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_channelData_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_electronicSerialNumber_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_interMSCCircuitID_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_interSwitchCount_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_mobileIdentificationNumber_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_servingCellID_impl },
  { BER_CLASS_CON, 18, BER_FLAGS_IMPLTAG, dissect_stationClassMark_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_targetCellID_impl },
  { BER_CLASS_CON, 39, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_confidentialityModes_impl },
  { BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_handoffReason_impl },
  { BER_CLASS_CON, 164, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_handoffState_impl },
  { BER_CLASS_CON, 45, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_signalingMessageEncryptionKey_impl },
  { BER_CLASS_CON, 31, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tdmaBurstIndicator_impl },
  { BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tdmaCallMode_impl },
  { BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tdmaChannelData_impl },
  { BER_CLASS_CON, 48, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_voicePrivacyMask_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_FacilitiesDirective(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              FacilitiesDirective_set, hf_index, ett_ansi_map_FacilitiesDirective);

  return offset;
}
static int dissect_facilitiesDirective(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_FacilitiesDirective(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_facilitiesDirective);
}


static const ber_sequence_t FacilitiesDirectiveRes_set[] = {
  { BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_channelData_impl },
  { BER_CLASS_CON, 39, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_confidentialityModes_impl },
  { BER_CLASS_CON, 31, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tdmaBurstIndicator_impl },
  { BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tdmaChannelData_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_FacilitiesDirectiveRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              FacilitiesDirectiveRes_set, hf_index, ett_ansi_map_FacilitiesDirectiveRes);

  return offset;
}
static int dissect_facilitiesDirectiveRes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_FacilitiesDirectiveRes(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_facilitiesDirectiveRes);
}



static int
dissect_ansi_map_BaseStationManufacturerCode(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_baseStationManufacturerCode_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_BaseStationManufacturerCode(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_baseStationManufacturerCode);
}



static int
dissect_ansi_map_AlertCode(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 112 "ansi_map.cnf"
	tvbuff_t *parameter_tvb = NULL;
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       &parameter_tvb);

	if (parameter_tvb){
		dissect_ansi_map_alertcode(parameter_tvb,pinfo,tree);
	}



  return offset;
}
static int dissect_alertCode_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_AlertCode(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_alertCode);
}



static int
dissect_ansi_map_CDMA2000HandoffInvokeIOSData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 436 "ansi_map.cnf"
	tvbuff_t *parameter_tvb = NULL;
	proto_item *item;
    proto_tree *subtree;

  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       &parameter_tvb);

	if (parameter_tvb){
		item = get_ber_last_created_item();
		subtree = proto_item_add_subtree(item, ett_CDMA2000HandoffInvokeIOSData);
		dissect_cdma2000_a1_elements(parameter_tvb, pinfo, subtree, 
			0, tvb_length_remaining(parameter_tvb,0));
	}


  return offset;
}
static int dissect_cdma2000HandoffInvokeIOSData_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_CDMA2000HandoffInvokeIOSData(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_cdma2000HandoffInvokeIOSData);
}



static int
dissect_ansi_map_CDMACallMode(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 152 "ansi_map.cnf"
	tvbuff_t *parameter_tvb = NULL;
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       &parameter_tvb);

	if (parameter_tvb){
		dissect_ansi_map_cdmacallmode(parameter_tvb,pinfo,tree);
	}


  return offset;
}
static int dissect_cdmaCallMode_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_CDMACallMode(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_cdmaCallMode);
}



static int
dissect_ansi_map_CDMAChannelData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 159 "ansi_map.cnf"
	tvbuff_t *parameter_tvb = NULL;
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       &parameter_tvb);

	if (parameter_tvb){
		dissect_ansi_map_cdmachanneldata(parameter_tvb,pinfo,tree);
	}



  return offset;
}
static int dissect_cdmaChannelData_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_CDMAChannelData(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_cdmaChannelData);
}



static int
dissect_ansi_map_CDMAConnectionReference(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_cdmaConnectionReference_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_CDMAConnectionReference(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_cdmaConnectionReference);
}



static int
dissect_ansi_map_CDMAServiceOption(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 393 "ansi_map.cnf"
	tvbuff_t *parameter_tvb = NULL;
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       &parameter_tvb);

	if (parameter_tvb){
		dissect_ansi_map_cdmaserviceoption(parameter_tvb,pinfo,tree);
	}




  return offset;
}
static int dissect_cdmaServiceOption_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_CDMAServiceOption(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_cdmaServiceOption);
}
static int dissect_CDMAServiceOptionList_item_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_CDMAServiceOption(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_CDMAServiceOptionList_item);
}



static int
dissect_ansi_map_CDMAState(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_cdmaState_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_CDMAState(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_cdmaState);
}



static int
dissect_ansi_map_DataPrivacyParameters(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_dataPrivacyParameters_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_DataPrivacyParameters(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_dataPrivacyParameters);
}



static int
dissect_ansi_map_CDMAServiceOptionConnectionIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_cdmaServiceOptionConnectionIdentifier_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_CDMAServiceOptionConnectionIdentifier(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_cdmaServiceOptionConnectionIdentifier);
}


static const ber_sequence_t CDMAConnectionReferenceInformation_sequence[] = {
  { BER_CLASS_CON, 208, BER_FLAGS_IMPLTAG, dissect_cdmaConnectionReference_impl },
  { BER_CLASS_CON, 175, BER_FLAGS_IMPLTAG, dissect_cdmaServiceOption_impl },
  { BER_CLASS_CON, 213, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaState_impl },
  { BER_CLASS_CON, 216, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dataPrivacyParameters_impl },
  { BER_CLASS_CON, 361, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaServiceOptionConnectionIdentifier_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_CDMAConnectionReferenceInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   CDMAConnectionReferenceInformation_sequence, hf_index, ett_ansi_map_CDMAConnectionReferenceInformation);

  return offset;
}
static int dissect_cdmaConnectionReferenceInformation_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_CDMAConnectionReferenceInformation(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_cdmaConnectionReferenceInformation);
}
static int dissect_cdmaConnectionReferenceInformation2_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_CDMAConnectionReferenceInformation(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_cdmaConnectionReferenceInformation2);
}


static const ber_sequence_t CDMAConnectionReferenceList_item_sequence[] = {
  { BER_CLASS_CON, 211, BER_FLAGS_IMPLTAG, dissect_cdmaConnectionReferenceInformation_impl },
  { BER_CLASS_CON, 211, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaConnectionReferenceInformation2_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_CDMAConnectionReferenceList_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   CDMAConnectionReferenceList_item_sequence, hf_index, ett_ansi_map_CDMAConnectionReferenceList_item);

  return offset;
}
static int dissect_CDMAConnectionReferenceList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_CDMAConnectionReferenceList_item(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_CDMAConnectionReferenceList_item);
}


static const ber_sequence_t CDMAConnectionReferenceList_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_CDMAConnectionReferenceList_item },
};

static int
dissect_ansi_map_CDMAConnectionReferenceList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      CDMAConnectionReferenceList_sequence_of, hf_index, ett_ansi_map_CDMAConnectionReferenceList);

  return offset;
}
static int dissect_cdmaConnectionReferenceList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_CDMAConnectionReferenceList(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_cdmaConnectionReferenceList);
}



static int
dissect_ansi_map_CDMAMobileProtocolRevision(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_cdmaMobileProtocolRevision_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_CDMAMobileProtocolRevision(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_cdmaMobileProtocolRevision);
}



static int
dissect_ansi_map_CDMAMSMeasuredChannelIdentity(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_cdmaMSMeasuredChannelIdentity_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_CDMAMSMeasuredChannelIdentity(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_cdmaMSMeasuredChannelIdentity);
}



static int
dissect_ansi_map_CDMAServiceConfigurationRecord(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_cdmaServiceConfigurationRecord_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_CDMAServiceConfigurationRecord(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_cdmaServiceConfigurationRecord);
}


static const ber_sequence_t CDMAServiceOptionList_sequence_of[1] = {
  { BER_CLASS_CON, 175, BER_FLAGS_IMPLTAG, dissect_CDMAServiceOptionList_item_impl },
};

static int
dissect_ansi_map_CDMAServiceOptionList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      CDMAServiceOptionList_sequence_of, hf_index, ett_ansi_map_CDMAServiceOptionList);

  return offset;
}
static int dissect_cdmaServiceOptionList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_CDMAServiceOptionList(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_cdmaServiceOptionList);
}



static int
dissect_ansi_map_CDMAServingOneWayDelay(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_cdmaServingOneWayDelay_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_CDMAServingOneWayDelay(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_cdmaServingOneWayDelay);
}



static int
dissect_ansi_map_CDMAStationClassMark(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 167 "ansi_map.cnf"
	tvbuff_t *parameter_tvb = NULL;
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       &parameter_tvb);

	if (parameter_tvb){
		dissect_ansi_map_cdmastationclassmark(parameter_tvb,pinfo,tree);
	}



  return offset;
}
static int dissect_cdmaStationClassMark_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_CDMAStationClassMark(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_cdmaStationClassMark);
}



static int
dissect_ansi_map_CDMAStationClassMark2(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_cdmaStationClassMark2_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_CDMAStationClassMark2(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_cdmaStationClassMark2);
}



static int
dissect_ansi_map_CDMAPilotStrength(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_cdmaPilotStrength_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_CDMAPilotStrength(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_cdmaPilotStrength);
}



static int
dissect_ansi_map_CDMATargetOneWayDelay(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_cdmaTargetOneWayDelay_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_CDMATargetOneWayDelay(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_cdmaTargetOneWayDelay);
}


static const ber_sequence_t CDMATargetMAHOInformation_sequence[] = {
  { BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_targetCellID_impl },
  { BER_CLASS_CON, 65, BER_FLAGS_IMPLTAG, dissect_cdmaPilotStrength_impl },
  { BER_CLASS_CON, 61, BER_FLAGS_IMPLTAG, dissect_cdmaTargetOneWayDelay_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_CDMATargetMAHOInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   CDMATargetMAHOInformation_sequence, hf_index, ett_ansi_map_CDMATargetMAHOInformation);

  return offset;
}
static int dissect_CDMATargetMAHOList_item_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_CDMATargetMAHOInformation(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_CDMATargetMAHOList_item);
}


static const ber_sequence_t CDMATargetMAHOList_sequence_of[1] = {
  { BER_CLASS_CON, 135, BER_FLAGS_IMPLTAG, dissect_CDMATargetMAHOList_item_impl },
};

static int
dissect_ansi_map_CDMATargetMAHOList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      CDMATargetMAHOList_sequence_of, hf_index, ett_ansi_map_CDMATargetMAHOList);

  return offset;
}
static int dissect_cdmaTargetMAHOList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_CDMATargetMAHOList(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_cdmaTargetMAHOList);
}



static int
dissect_ansi_map_CDMASignalQuality(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_cdmaSignalQuality_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_CDMASignalQuality(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_cdmaSignalQuality);
}


static const ber_sequence_t CDMATargetMeasurementInformation_sequence[] = {
  { BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_targetCellID_impl },
  { BER_CLASS_CON, 64, BER_FLAGS_IMPLTAG, dissect_cdmaSignalQuality_impl },
  { BER_CLASS_CON, 61, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaTargetOneWayDelay_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_CDMATargetMeasurementInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   CDMATargetMeasurementInformation_sequence, hf_index, ett_ansi_map_CDMATargetMeasurementInformation);

  return offset;
}
static int dissect_CDMATargetMeasurementList_item_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_CDMATargetMeasurementInformation(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_CDMATargetMeasurementList_item);
}


static const ber_sequence_t CDMATargetMeasurementList_sequence_of[1] = {
  { BER_CLASS_CON, 133, BER_FLAGS_IMPLTAG, dissect_CDMATargetMeasurementList_item_impl },
};

static int
dissect_ansi_map_CDMATargetMeasurementList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      CDMATargetMeasurementList_sequence_of, hf_index, ett_ansi_map_CDMATargetMeasurementList);

  return offset;
}
static int dissect_cdmaTargetMeasurementList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_CDMATargetMeasurementList(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_cdmaTargetMeasurementList);
}



static int
dissect_ansi_map_ISLPInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_ilspInformation_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_ISLPInformation(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_ilspInformation);
}



static int
dissect_ansi_map_MSLocation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 255 "ansi_map.cnf"
	tvbuff_t *parameter_tvb = NULL;
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       &parameter_tvb);

	if (parameter_tvb){
		dissect_ansi_map_mscid(parameter_tvb,pinfo,tree);
	}



  return offset;
}
static int dissect_msLocation_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_MSLocation(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_msLocation);
}



static int
dissect_ansi_map_NAMPSCallMode(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 263 "ansi_map.cnf"
	tvbuff_t *parameter_tvb = NULL;
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       &parameter_tvb);

	if (parameter_tvb){
		dissect_ansi_map_nampscallmode(parameter_tvb,pinfo,tree);
	}



  return offset;
}
static int dissect_nampsCallMode_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_NAMPSCallMode(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_nampsCallMode);
}



static int
dissect_ansi_map_NAMPSChannelData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 271 "ansi_map.cnf"
	tvbuff_t *parameter_tvb = NULL;
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       &parameter_tvb);

	if (parameter_tvb){
		dissect_ansi_map_nampschanneldata(parameter_tvb,pinfo,tree);
	}



  return offset;
}
static int dissect_nampsChannelData_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_NAMPSChannelData(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_nampsChannelData);
}



static int
dissect_ansi_map_NonPublicData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_nonPublicData_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_NonPublicData(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_nonPublicData);
}



static int
dissect_ansi_map_PDSNAddress(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_pdsnAddress_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_PDSNAddress(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_pdsnAddress);
}



static int
dissect_ansi_map_PDSNProtocolType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_pdsnProtocolType_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_PDSNProtocolType(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_pdsnProtocolType);
}



static int
dissect_ansi_map_QoSPriority(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_qosPriority_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_QoSPriority(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_qosPriority);
}



static int
dissect_ansi_map_SystemOperatorCode(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_systemOperatorCode_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_SystemOperatorCode(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_systemOperatorCode);
}



static int
dissect_ansi_map_TDMABandwidth(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_tdmaBandwidth_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_TDMABandwidth(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_tdmaBandwidth);
}



static int
dissect_ansi_map_TDMAServiceCode(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_tdmaServiceCode_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_TDMAServiceCode(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_tdmaServiceCode);
}



static int
dissect_ansi_map_TDMATerminalCapability(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_tdmaTerminalCapability(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_TDMATerminalCapability(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_tdmaTerminalCapability);
}
static int dissect_tdmaTerminalCapability_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_TDMATerminalCapability(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_tdmaTerminalCapability);
}



static int
dissect_ansi_map_TDMAVoiceCoder(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_tdmaVoiceCoder_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_TDMAVoiceCoder(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_tdmaVoiceCoder);
}



static int
dissect_ansi_map_UserZoneData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_userZoneData_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_UserZoneData(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_userZoneData);
}


static const ber_sequence_t FacilitiesDirective2_set[] = {
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_billingID_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_channelData_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_electronicSerialNumber_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_interMSCCircuitID_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_interSwitchCount_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_mobileIdentificationNumber_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_servingCellID_impl },
  { BER_CLASS_CON, 197, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_baseStationManufacturerCode_impl },
  { BER_CLASS_CON, 75, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_alertCode_impl },
  { BER_CLASS_CON, 356, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdma2000HandoffInvokeIOSData_impl },
  { BER_CLASS_CON, 62, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaCallMode_impl },
  { BER_CLASS_CON, 63, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaChannelData_impl },
  { BER_CLASS_CON, 212, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaConnectionReferenceList_impl },
  { BER_CLASS_CON, 66, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaMobileProtocolRevision_impl },
  { BER_CLASS_CON, 351, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaMSMeasuredChannelIdentity_impl },
  { BER_CLASS_CON, 67, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaPrivateLongCodeMask_impl },
  { BER_CLASS_CON, 174, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaServiceConfigurationRecord_impl },
  { BER_CLASS_CON, 176, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaServiceOptionList_impl },
  { BER_CLASS_CON, 60, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaServingOneWayDelay_impl },
  { BER_CLASS_CON, 59, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaStationClassMark_impl },
  { BER_CLASS_CON, 177, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaStationClassMark2_impl },
  { BER_CLASS_CON, 136, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaTargetMAHOList_impl },
  { BER_CLASS_CON, 134, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaTargetMeasurementList_impl },
  { BER_CLASS_CON, 39, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_confidentialityModes_impl },
  { BER_CLASS_CON, 215, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dataKey_impl },
  { BER_CLASS_CON, 216, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dataPrivacyParameters_impl },
  { BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_handoffReason_impl },
  { BER_CLASS_CON, 164, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_handoffState_impl },
  { BER_CLASS_CON, 217, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ilspInformation_impl },
  { BER_CLASS_CON, 70, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_msLocation_impl },
  { BER_CLASS_CON, 165, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_nampsCallMode_impl },
  { BER_CLASS_CON, 74, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_nampsChannelData_impl },
  { BER_CLASS_CON, 40, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_randomVariable_impl },
  { BER_CLASS_CON, 200, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_nonPublicData_impl },
  { BER_CLASS_CON, 349, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pdsnAddress_impl },
  { BER_CLASS_CON, 350, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pdsnProtocolType_impl },
  { BER_CLASS_CON, 348, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_qosPriority_impl },
  { BER_CLASS_CON, 45, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_signalingMessageEncryptionKey_impl },
  { BER_CLASS_CON, 18, BER_FLAGS_IMPLTAG, dissect_stationClassMark_impl },
  { BER_CLASS_CON, 206, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_systemOperatorCode_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_targetCellID_impl },
  { BER_CLASS_CON, 220, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tdmaBandwidth_impl },
  { BER_CLASS_CON, 31, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tdmaBurstIndicator_impl },
  { BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tdmaCallMode_impl },
  { BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tdmaChannelData_impl },
  { BER_CLASS_CON, 178, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tdmaServiceCode_impl },
  { BER_CLASS_CON, 179, BER_FLAGS_OPTIONAL, dissect_tdmaTerminalCapability },
  { BER_CLASS_CON, 180, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tdmaVoiceCoder_impl },
  { BER_CLASS_CON, 47, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_terminalType_impl },
  { BER_CLASS_CON, 209, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_userZoneData_impl },
  { BER_CLASS_CON, 48, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_voicePrivacyMask_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_FacilitiesDirective2(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              FacilitiesDirective2_set, hf_index, ett_ansi_map_FacilitiesDirective2);

  return offset;
}
static int dissect_facilitiesDirective2(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_FacilitiesDirective2(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_facilitiesDirective2);
}



static int
dissect_ansi_map_BSMCStatus(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_bsmcstatus_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_BSMCStatus(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_bsmcstatus);
}



static int
dissect_ansi_map_CDMA2000HandoffResponseIOSData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 449 "ansi_map.cnf"
	tvbuff_t *parameter_tvb = NULL;
	proto_item *item;
    proto_tree *subtree;

  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       &parameter_tvb);

	if (parameter_tvb){
		item = get_ber_last_created_item();
		subtree = proto_item_add_subtree(item, ett_CDMA2000HandoffResponseIOSData);
		dissect_cdma2000_a1_elements(parameter_tvb, pinfo, subtree, 
			0, tvb_length_remaining(parameter_tvb,0));
	}


  return offset;
}
static int dissect_cdma2000HandoffResponseIOSData_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_CDMA2000HandoffResponseIOSData(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_cdma2000HandoffResponseIOSData);
}



static int
dissect_ansi_map_CDMACodeChannel(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_cdmaCodeChannel_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_CDMACodeChannel(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_cdmaCodeChannel);
}



static int
dissect_ansi_map_CDMAPilotPN(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_cdmaPilotPN_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_CDMAPilotPN(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_cdmaPilotPN);
}



static int
dissect_ansi_map_CDMAPowerCombinedIndicator(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_cdmaPowerCombinedIndicator_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_CDMAPowerCombinedIndicator(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_cdmaPowerCombinedIndicator);
}


static const ber_sequence_t CDMACodeChannelInformation_sequence[] = {
  { BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_targetCellID_impl },
  { BER_CLASS_CON, 68, BER_FLAGS_IMPLTAG, dissect_cdmaCodeChannel_impl },
  { BER_CLASS_CON, 173, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaPilotPN_impl },
  { BER_CLASS_CON, 228, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaPowerCombinedIndicator_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_CDMACodeChannelInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   CDMACodeChannelInformation_sequence, hf_index, ett_ansi_map_CDMACodeChannelInformation);

  return offset;
}
static int dissect_CDMACodeChannelList_item_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_CDMACodeChannelInformation(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_CDMACodeChannelList_item);
}


static const ber_sequence_t CDMACodeChannelList_sequence_of[1] = {
  { BER_CLASS_CON, 131, BER_FLAGS_IMPLTAG, dissect_CDMACodeChannelList_item_impl },
};

static int
dissect_ansi_map_CDMACodeChannelList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      CDMACodeChannelList_sequence_of, hf_index, ett_ansi_map_CDMACodeChannelList);

  return offset;
}
static int dissect_cdmaCodeChannelList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_CDMACodeChannelList(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_cdmaCodeChannelList);
}



static int
dissect_ansi_map_CDMASearchParameters(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_cdmaSearchParameters_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_CDMASearchParameters(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_cdmaSearchParameters);
}



static int
dissect_ansi_map_CDMASearchWindow(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_cdmaSearchWindow_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_CDMASearchWindow(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_cdmaSearchWindow);
}



static int
dissect_ansi_map_SOCStatus(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_sOCStatus_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_SOCStatus(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_sOCStatus);
}


static const ber_sequence_t FacilitiesDirective2Res_set[] = {
  { BER_CLASS_CON, 198, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_bsmcstatus_impl },
  { BER_CLASS_CON, 357, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdma2000HandoffResponseIOSData_impl },
  { BER_CLASS_CON, 63, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaChannelData_impl },
  { BER_CLASS_CON, 132, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaCodeChannelList_impl },
  { BER_CLASS_CON, 212, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaConnectionReferenceList_impl },
  { BER_CLASS_CON, 230, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaSearchParameters_impl },
  { BER_CLASS_CON, 69, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaSearchWindow_impl },
  { BER_CLASS_CON, 174, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaServiceConfigurationRecord_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_channelData_impl },
  { BER_CLASS_CON, 39, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_confidentialityModes_impl },
  { BER_CLASS_CON, 217, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ilspInformation_impl },
  { BER_CLASS_CON, 74, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_nampsChannelData_impl },
  { BER_CLASS_CON, 205, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sOCStatus_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_targetCellID_impl },
  { BER_CLASS_CON, 31, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tdmaBurstIndicator_impl },
  { BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tdmaChannelData_impl },
  { BER_CLASS_CON, 180, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tdmaVoiceCoder_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_FacilitiesDirective2Res(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              FacilitiesDirective2Res_set, hf_index, ett_ansi_map_FacilitiesDirective2Res);

  return offset;
}
static int dissect_facilitiesDirective2Res(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_FacilitiesDirective2Res(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_facilitiesDirective2Res);
}


static const value_string ansi_map_ReleaseReason_vals[] = {
  {   0, "unspecified" },
  {   1, "callOverClearForward" },
  {   2, "callOverClearBackward" },
  {   3, "handoffSuccessful" },
  {   4, "handoffAbort-call-over" },
  {   5, "handoffAbort-not-received" },
  {   6, "abnormalMobileTermination" },
  {   7, "abnormalSwitchTermination" },
  {   8, "specialFeatureRelease" },
  {   9, "sessionOverClearForward" },
  {  10, "sessionOverClearBackward" },
  {  11, "clearAllServicesForward" },
  {  12, "clearAllServicesBackward" },
  {  13, "anchor-MSC-was-removed-from-the-packet-data-session" },
  {  14, "keep-MS-on-traffic-channel" },
  { 0, NULL }
};


static int
dissect_ansi_map_ReleaseReason(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_releaseReason_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_ReleaseReason(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_releaseReason);
}


static const ber_sequence_t FacilitiesRelease_set[] = {
  { BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_interMSCCircuitID_impl },
  { BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_releaseReason_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_billingID_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mobileIdentificationNumber_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_FacilitiesRelease(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              FacilitiesRelease_set, hf_index, ett_ansi_map_FacilitiesRelease);

  return offset;
}
static int dissect_facilitiesRelease(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_FacilitiesRelease(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_facilitiesRelease);
}


static const ber_sequence_t FacilitiesReleaseRes_set[] = {
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_billingID_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_FacilitiesReleaseRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              FacilitiesReleaseRes_set, hf_index, ett_ansi_map_FacilitiesReleaseRes);

  return offset;
}
static int dissect_facilitiesReleaseRes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_FacilitiesReleaseRes(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_facilitiesReleaseRes);
}



static int
dissect_ansi_map_ACGEncountered(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_acgencountered_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_ACGEncountered(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_acgencountered);
}



static int
dissect_ansi_map_CallingPartyName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 404 "ansi_map.cnf"
	tvbuff_t *parameter_tvb = NULL;
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       &parameter_tvb);

	if (parameter_tvb){
		dissect_ansi_map_callingpartyname(parameter_tvb,pinfo,tree);
	}



  return offset;
}
static int dissect_callingPartyName_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_CallingPartyName(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_callingPartyName);
}



static int
dissect_ansi_map_CallingPartyNumberDigits1(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ansi_map_DigitsType(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_callingPartyNumberDigits1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_CallingPartyNumberDigits1(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_callingPartyNumberDigits1);
}



static int
dissect_ansi_map_CallingPartyNumberDigits2(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ansi_map_DigitsType(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_callingPartyNumberDigits2_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_CallingPartyNumberDigits2(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_callingPartyNumberDigits2);
}



static int
dissect_ansi_map_Subaddress(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 104 "ansi_map.cnf"
	tvbuff_t *parameter_tvb = NULL;
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       &parameter_tvb);

	if (parameter_tvb){
		dissect_ansi_map_subaddress(parameter_tvb,pinfo,tree);
	}



  return offset;
}



static int
dissect_ansi_map_CallingPartySubaddress(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ansi_map_Subaddress(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_callingPartySubaddress_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_CallingPartySubaddress(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_callingPartySubaddress);
}



static int
dissect_ansi_map_ConferenceCallingIndicator(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_conferenceCallingIndicator_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_ConferenceCallingIndicator(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_conferenceCallingIndicator);
}



static int
dissect_ansi_map_MobileDirectoryNumber(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ansi_map_DigitsType(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_mobileDirectoryNumber_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_MobileDirectoryNumber(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_mobileDirectoryNumber);
}



static int
dissect_ansi_map_MSCIdentificationNumber(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ansi_map_DigitsType(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_mSCIdentificationNumber_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_MSCIdentificationNumber(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_mSCIdentificationNumber);
}



static int
dissect_ansi_map_OneTimeFeatureIndicator(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 279 "ansi_map.cnf"
	tvbuff_t *parameter_tvb = NULL;
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       &parameter_tvb);

	if (parameter_tvb){
		dissect_ansi_map_onetimefeatureindicator(parameter_tvb,pinfo,tree);
	}



  return offset;
}
static int dissect_oneTimeFeatureIndicator_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_OneTimeFeatureIndicator(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_oneTimeFeatureIndicator);
}


static const ber_sequence_t FeatureRequest_set[] = {
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_billingID_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_digits_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_electronicSerialNumber_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_interMSCCircuitID_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_interSwitchCount_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_mobileIdentificationNumber_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_servingCellID_impl },
  { BER_CLASS_CON, 340, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_acgencountered_impl },
  { BER_CLASS_CON, 243, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyName_impl },
  { BER_CLASS_CON, 80, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyNumberDigits1_impl },
  { BER_CLASS_CON, 81, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyNumberDigits2_impl },
  { BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartySubaddress_impl },
  { BER_CLASS_CON, 62, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaCallMode_impl },
  { BER_CLASS_CON, 63, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaChannelData_impl },
  { BER_CLASS_CON, 66, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaMobileProtocolRevision_impl },
  { BER_CLASS_CON, 67, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaPrivateLongCodeMask_impl },
  { BER_CLASS_CON, 60, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaServingOneWayDelay_impl },
  { BER_CLASS_CON, 59, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaStationClassMark_impl },
  { BER_CLASS_CON, 136, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaTargetMAHOList_impl },
  { BER_CLASS_CON, 134, BER_FLAGS_IMPLTAG, dissect_cdmaTargetMeasurementList_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_channelData_impl },
  { BER_CLASS_CON, 137, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_conferenceCallingIndicator_impl },
  { BER_CLASS_CON, 39, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_confidentialityModes_impl },
  { BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_handoffReason_impl },
  { BER_CLASS_CON, 164, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_handoffState_impl },
  { BER_CLASS_CON, 93, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mobileDirectoryNumber_impl },
  { BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mscid_impl },
  { BER_CLASS_CON, 94, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mSCIdentificationNumber_impl },
  { BER_CLASS_CON, 70, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_msLocation_impl },
  { BER_CLASS_CON, 97, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_oneTimeFeatureIndicator_impl },
  { BER_CLASS_CON, 32, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pc_ssn_impl },
  { BER_CLASS_CON, 165, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_nampsCallMode_impl },
  { BER_CLASS_CON, 74, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_nampsChannelData_impl },
  { BER_CLASS_CON, 103, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_senderIdentificationNumber_impl },
  { BER_CLASS_CON, 45, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_signalingMessageEncryptionKey_impl },
  { BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_stationClassMark_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_targetCellID_impl },
  { BER_CLASS_CON, 31, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tdmaBurstIndicator_impl },
  { BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tdmaCallMode_impl },
  { BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tdmaChannelData_impl },
  { BER_CLASS_CON, 123, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_transactionCapability_impl },
  { BER_CLASS_CON, 48, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_voicePrivacyMask_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_FeatureRequest(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              FeatureRequest_set, hf_index, ett_ansi_map_FeatureRequest);

  return offset;
}
static int dissect_featureRequest(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_FeatureRequest(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_featureRequest);
}


static const value_string ansi_map_FeatureResult_vals[] = {
  {   0, "not-used" },
  {   1, "unsuccessful" },
  {   2, "successful" },
  { 0, NULL }
};


static int
dissect_ansi_map_FeatureResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_featureResult_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_FeatureResult(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_featureResult);
}


static const value_string ansi_map_AccessDeniedReason_vals[] = {
  {   0, "not-used" },
  {   1, "unassigned-directory-number" },
  {   2, "inactive" },
  {   3, "busy" },
  {   4, "termination-denied" },
  {   5, "no-page-response" },
  {   6, "unavailable" },
  {   7, "service-Rejected-by-MS" },
  {   8, "services-Rejected-by-the-System" },
  {   9, "service-Type-Mismatch" },
  {  10, "service-Denied" },
  { 0, NULL }
};


static int
dissect_ansi_map_AccessDeniedReason(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_accessDeniedReason_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_AccessDeniedReason(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_accessDeniedReason);
}



static int
dissect_ansi_map_ActionCode(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_actionCode_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_ActionCode(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_actionCode);
}
static int dissect_ctionCode_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_ActionCode(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_ctionCode);
}



static int
dissect_ansi_map_AnnouncementCode(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 120 "ansi_map.cnf"
	tvbuff_t *parameter_tvb = NULL;
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       &parameter_tvb);

	if (parameter_tvb){
		dissect_ansi_map_announcementcode(parameter_tvb,pinfo,tree);
	}



  return offset;
}
static int dissect_announcementCode1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_AnnouncementCode(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_announcementCode1);
}
static int dissect_announcementCode2_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_AnnouncementCode(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_announcementCode2);
}


static const ber_sequence_t AnnouncementList_sequence[] = {
  { BER_CLASS_CON, 76, BER_FLAGS_IMPLTAG, dissect_announcementCode1_impl },
  { BER_CLASS_CON, 76, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_announcementCode2_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_AnnouncementList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   AnnouncementList_sequence, hf_index, ett_ansi_map_AnnouncementList);

  return offset;
}
static int dissect_announcementList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_AnnouncementList(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_announcementList);
}



static int
dissect_ansi_map_CallingPartyNumberString1(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ansi_map_DigitsType(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_callingPartyNumberString1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_CallingPartyNumberString1(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_callingPartyNumberString1);
}



static int
dissect_ansi_map_CallingPartyNumberString2(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ansi_map_DigitsType(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_callingPartyNumberString2_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_CallingPartyNumberString2(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_callingPartyNumberString2);
}



static int
dissect_ansi_map_DisplayText(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_displayText_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_DisplayText(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_displayText);
}



static int
dissect_ansi_map_DisplayText2(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_displayText2_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_DisplayText2(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_displayText2);
}



static int
dissect_ansi_map_DMH_AccountCodeDigits(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ansi_map_DigitsType(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_dmh_AccountCodeDigits_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_DMH_AccountCodeDigits(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_dmh_AccountCodeDigits);
}



static int
dissect_ansi_map_DMH_AlternateBillingDigits(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ansi_map_DigitsType(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_dmh_AlternateBillingDigits_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_DMH_AlternateBillingDigits(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_dmh_AlternateBillingDigits);
}



static int
dissect_ansi_map_DMH_BillingDigits(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ansi_map_DigitsType(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_dmh_BillingDigits_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_DMH_BillingDigits(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_dmh_BillingDigits);
}


static const value_string ansi_map_DMH_RedirectionIndicator_vals[] = {
  {   0, "not-specified" },
  {   1, "cfu" },
  {   2, "cfb" },
  {   3, "cfna" },
  {   4, "cfo" },
  {   5, "cd-Unspecified" },
  {   6, "cd-PSTN" },
  {   7, "cd-Private" },
  {   8, "pstn-Tandem" },
  {   9, "private" },
  {  10, "busy" },
  {  11, "inactive" },
  {  12, "unassigned" },
  {  13, "termination-denied" },
  {  14, "cd-failure" },
  {  15, "ect" },
  {  16, "mah" },
  {  17, "fa" },
  {  18, "abandoned-call-leg" },
  {  19, "pca-call-refused" },
  {  20, "sca-call-refused" },
  {  21, "dialogue" },
  {  22, "cfd" },
  {  23, "cd-local" },
  {  24, "voice-mail-retrieval" },
  { 0, NULL }
};


static int
dissect_ansi_map_DMH_RedirectionIndicator(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_dmh_RedirectionIndicator_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_DMH_RedirectionIndicator(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_dmh_RedirectionIndicator);
}



static int
dissect_ansi_map_GroupInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_groupInformation(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_GroupInformation(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_groupInformation);
}
static int dissect_groupInformation_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_GroupInformation(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_groupInformation);
}



static int
dissect_ansi_map_NoAnswerTime(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_noAnswerTime_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_NoAnswerTime(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_noAnswerTime);
}



static int
dissect_ansi_map_PACAIndicator(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 295 "ansi_map.cnf"
	tvbuff_t *parameter_tvb = NULL;
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       &parameter_tvb);

	if (parameter_tvb){
		dissect_ansi_map_pacaindicator(parameter_tvb,pinfo,tree);
	}



  return offset;
}
static int dissect_pACAIndicator_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_PACAIndicator(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_pACAIndicator);
}



static int
dissect_ansi_map_PilotNumber(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ansi_map_DigitsType(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_pilotNumber_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_PilotNumber(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_pilotNumber);
}



static int
dissect_ansi_map_PreferredLanguageIndicator(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_preferredLanguageIndicator_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_PreferredLanguageIndicator(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_preferredLanguageIndicator);
}



static int
dissect_ansi_map_RedirectingNumberDigits(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ansi_map_DigitsType(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_redirectingNumberDigits_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_RedirectingNumberDigits(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_redirectingNumberDigits);
}
static int dissect_edirectingNumberDigits_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_RedirectingNumberDigits(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_edirectingNumberDigits);
}



static int
dissect_ansi_map_RedirectingNumberString(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ansi_map_DigitsType(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_redirectingNumberString_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_RedirectingNumberString(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_redirectingNumberString);
}



static int
dissect_ansi_map_RedirectingSubaddress(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ansi_map_Subaddress(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_redirectingSubaddress_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_RedirectingSubaddress(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_redirectingSubaddress);
}
static int dissect_edirectingSubaddress_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_RedirectingSubaddress(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_edirectingSubaddress);
}


static const value_string ansi_map_ResumePIC_vals[] = {
  {   1, "continue-Call-Processing" },
  {   2, "collect-Information-PIC" },
  {   3, "analyze-Information-PIC" },
  {   4, "select-Route-PIC" },
  {   5, "authorize-Origination-Attempt-PIC" },
  {   6, "authorize-Call-Setup-PIC" },
  {   7, "send-Call-PIC" },
  {   8, "o-Alerting-PIC" },
  {   9, "o-Active-PIC" },
  {  10, "o-Suspended-PIC" },
  {  11, "o-Null-PIC" },
  {  32, "select-Facility-PIC" },
  {  33, "present-Call-PIC" },
  {  34, "authorize-Termination-Attempt-PIC" },
  {  35, "t-Alerting-PIC" },
  {  36, "t-Active-PIC" },
  {  37, "t-Suspended-PIC" },
  {  38, "t-Null-PIC" },
  { 0, NULL }
};


static int
dissect_ansi_map_ResumePIC(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_resumePIC_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_ResumePIC(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_resumePIC);
}



static int
dissect_ansi_map_LegInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_legInformation_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_LegInformation(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_legInformation);
}



static int
dissect_ansi_map_TerminationTriggers(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 377 "ansi_map.cnf"
	tvbuff_t *parameter_tvb = NULL;
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       &parameter_tvb);

	if (parameter_tvb){
		dissect_ansi_map_terminationtriggers(parameter_tvb,pinfo,tree);
	}



  return offset;
}
static int dissect_terminationTriggers_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_TerminationTriggers(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_terminationTriggers);
}


static const ber_sequence_t IntersystemTermination_sequence[] = {
  { BER_CLASS_CON, 87, BER_FLAGS_IMPLTAG, dissect_destinationDigits_impl },
  { BER_CLASS_CON, 21, BER_FLAGS_IMPLTAG, dissect_mscid_impl },
  { BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_accessDeniedReason_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_billingID_impl },
  { BER_CLASS_CON, 86, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_carrierDigits_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_electronicSerialNumber_impl },
  { BER_CLASS_CON, 242, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_imsi_impl },
  { BER_CLASS_CON, 288, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_legInformation_impl },
  { BER_CLASS_CON, 93, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mobileDirectoryNumber_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mobileIdentificationNumber_impl },
  { BER_CLASS_CON, 94, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mSCIdentificationNumber_impl },
  { BER_CLASS_CON, 150, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_routingDigits_impl },
  { BER_CLASS_CON, 122, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_terminationTriggers_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_IntersystemTermination(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   IntersystemTermination_sequence, hf_index, ett_ansi_map_IntersystemTermination);

  return offset;
}
static int dissect_intersystemTermination_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_IntersystemTermination(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_intersystemTermination);
}



static int
dissect_ansi_map_TerminationTreatment(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_terminationTreatment_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_TerminationTreatment(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_terminationTreatment);
}



static int
dissect_ansi_map_VoiceMailboxPIN(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ansi_map_DigitsType(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_voiceMailboxPIN_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_VoiceMailboxPIN(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_voiceMailboxPIN);
}



static int
dissect_ansi_map_VoiceMailboxNumber(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ansi_map_DigitsType(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_voiceMailboxNumber_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_VoiceMailboxNumber(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_voiceMailboxNumber);
}


static const ber_sequence_t LocalTermination_sequence[] = {
  { BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_electronicSerialNumber_impl },
  { BER_CLASS_CON, 121, BER_FLAGS_IMPLTAG, dissect_terminationTreatment_impl },
  { BER_CLASS_CON, 75, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_alertCode_impl },
  { BER_CLASS_CON, 86, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_carrierDigits_impl },
  { BER_CLASS_CON, 87, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_destinationDigits_impl },
  { BER_CLASS_CON, 242, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_imsi_impl },
  { BER_CLASS_CON, 288, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_legInformation_impl },
  { BER_CLASS_CON, 93, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mobileDirectoryNumber_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_mobileIdentificationNumber_impl },
  { BER_CLASS_CON, 97, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_oneTimeFeatureIndicator_impl },
  { BER_CLASS_CON, 150, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_routingDigits_impl },
  { BER_CLASS_CON, 122, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_terminationTriggers_impl },
  { BER_CLASS_CON, 159, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_voiceMailboxPIN_impl },
  { BER_CLASS_CON, 160, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_voiceMailboxNumber_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_LocalTermination(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   LocalTermination_sequence, hf_index, ett_ansi_map_LocalTermination);

  return offset;
}
static int dissect_localTermination_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_LocalTermination(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_localTermination);
}


static const ber_sequence_t PSTNTermination_sequence[] = {
  { BER_CLASS_CON, 87, BER_FLAGS_IMPLTAG, dissect_destinationDigits_impl },
  { BER_CLASS_CON, 86, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_carrierDigits_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_electronicSerialNumber_impl },
  { BER_CLASS_CON, 242, BER_FLAGS_IMPLTAG, dissect_imsi_impl },
  { BER_CLASS_CON, 288, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_legInformation_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mobileIdentificationNumber_impl },
  { BER_CLASS_CON, 150, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_routingDigits_impl },
  { BER_CLASS_CON, 122, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_terminationTriggers_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_PSTNTermination(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   PSTNTermination_sequence, hf_index, ett_ansi_map_PSTNTermination);

  return offset;
}
static int dissect_pstnTermination_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_PSTNTermination(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_pstnTermination);
}


static const value_string ansi_map_TerminationList_item_vals[] = {
  {  89, "intersystemTermination" },
  {  91, "localTermination" },
  {  71, "pstnTermination" },
  { 0, NULL }
};

static const ber_choice_t TerminationList_item_choice[] = {
  {  89, BER_CLASS_CON, 89, BER_FLAGS_IMPLTAG, dissect_intersystemTermination_impl },
  {  91, BER_CLASS_CON, 91, BER_FLAGS_IMPLTAG, dissect_localTermination_impl },
  {  71, BER_CLASS_CON, 71, BER_FLAGS_IMPLTAG, dissect_pstnTermination_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_ansi_map_TerminationList_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 TerminationList_item_choice, hf_index, ett_ansi_map_TerminationList_item,
                                 NULL);

  return offset;
}
static int dissect_TerminationList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_TerminationList_item(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_TerminationList_item);
}


static const ber_sequence_t TerminationList_set_of[1] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_TerminationList_item },
};

static int
dissect_ansi_map_TerminationList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 TerminationList_set_of, hf_index, ett_ansi_map_TerminationList);

  return offset;
}
static int dissect_terminationList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_TerminationList(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_terminationList);
}



static int
dissect_ansi_map_GlobalTitle(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_globalTitle_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_GlobalTitle(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_globalTitle);
}


static const value_string ansi_map_DestinationAddress_vals[] = {
  { 389, "globalTitle" },
  {  32, "pC-SSN" },
  { 0, NULL }
};

static const ber_choice_t DestinationAddress_choice[] = {
  { 389, BER_CLASS_CON, 389, BER_FLAGS_IMPLTAG, dissect_globalTitle_impl },
  {  32, BER_CLASS_CON, 32, BER_FLAGS_IMPLTAG, dissect_pC_SSN_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_ansi_map_DestinationAddress(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 DestinationAddress_choice, hf_index, ett_ansi_map_DestinationAddress,
                                 NULL);

  return offset;
}
static int dissect_destinationAddress(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_DestinationAddress(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_destinationAddress);
}


static const value_string ansi_map_TriggerType_vals[] = {
  {   1, "all-Calls" },
  {   2, "double-Introducing-Star" },
  {   3, "single-Introducing-Star" },
  {   4, "reserved-for-Home-System-Feature-Code" },
  {   5, "double-Introducing-Pound" },
  {   6, "single-Introducing-Pound" },
  {   7, "revertive-Call" },
  {   8, "a0-Digit" },
  {   9, "a1-Digit" },
  {  10, "a2-Digit" },
  {  11, "a3-Digit" },
  {  12, "a4-Digit" },
  {  13, "a5-Digit" },
  {  14, "a6-Digit" },
  {  15, "a7-Digit" },
  {  16, "a8-Digit" },
  {  17, "a9-Digit" },
  {  18, "a10-Digit" },
  {  19, "a11-Digit" },
  {  20, "a12-Digit" },
  {  21, "a13-Digit" },
  {  22, "a14-Digit" },
  {  23, "a15-Digit" },
  {  24, "local-Call" },
  {  25, "intra-LATA-Toll-Call" },
  {  26, "inter-LATA-Toll-Call" },
  {  27, "world-Zone-Call" },
  {  28, "international-Call" },
  {  29, "unrecognized-Number" },
  {  30, "prior-Agreement" },
  {  31, "specific-Called-Party-Digit-String" },
  {  32, "mobile-Termination" },
  {  33, "advanced-Termination" },
  {  34, "location" },
  {  35, "locally-Allowed-Specific-Digit-String" },
  {  36, "origination-Attempt-Authorized" },
  {  37, "calling-Routing-Address-Available" },
  {  38, "initial-Termination" },
  {  39, "called-Routing-Address-Available" },
  {  40, "o-Answer" },
  {  41, "o-Disconnect" },
  {  42, "o-Called-Party-Busy" },
  {  43, "o-No-Answer" },
  {  64, "terminating-Resource-Available" },
  {  65, "t-Busy" },
  {  66, "t-No-Answer" },
  {  67, "t-No-Page-Response" },
  {  68, "t-Routable" },
  {  69, "t-Answer" },
  {  70, "t-Disconnect" },
  { 220, "reserved-for-TDP-R-DP-Type-value" },
  { 221, "reserved-for-TDP-N-DP-Type-value" },
  { 222, "reserved-for-EDP-R-DP-Type-value" },
  { 223, "reserved-for-EDP-N-DP-Type-value" },
  { 0, NULL }
};


static int
dissect_ansi_map_TriggerType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_triggerType_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_TriggerType(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_triggerType);
}


static const value_string ansi_map_DetectionPointType_vals[] = {
  {   1, "tDP-R" },
  {   2, "tDP-N" },
  {   3, "eDP-R" },
  {   4, "eDP-N" },
  { 0, NULL }
};


static int
dissect_ansi_map_DetectionPointType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_detectionPointType(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_DetectionPointType(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_detectionPointType);
}


static const ber_sequence_t WIN_Trigger_sequence[] = {
  { BER_CLASS_CON, 279, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_triggerType_impl },
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_detectionPointType },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_WIN_Trigger(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   WIN_Trigger_sequence, hf_index, ett_ansi_map_WIN_Trigger);

  return offset;
}
static int dissect_WIN_TriggerList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_WIN_Trigger(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_WIN_TriggerList_item);
}


static const ber_sequence_t WIN_TriggerList_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_WIN_TriggerList_item },
};

static int
dissect_ansi_map_WIN_TriggerList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 WIN_TriggerList_set_of, hf_index, ett_ansi_map_WIN_TriggerList);

  return offset;
}
static int dissect_wIN_TriggerList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_WIN_TriggerList(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_wIN_TriggerList);
}


static const ber_sequence_t TriggerList_set[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_destinationAddress },
  { BER_CLASS_CON, 283, BER_FLAGS_IMPLTAG, dissect_wIN_TriggerList_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_TriggerList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              TriggerList_set, hf_index, ett_ansi_map_TriggerList);

  return offset;
}
static int dissect_triggerList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_TriggerList(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_triggerList);
}
static int dissect_triggerListOpt_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_TriggerList(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_triggerListOpt);
}


static const ber_sequence_t TriggerAddressList_item_set[] = {
  { BER_CLASS_CON, 278, BER_FLAGS_IMPLTAG, dissect_triggerList_impl },
  { BER_CLASS_CON, 278, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_triggerListOpt_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_TriggerAddressList_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              TriggerAddressList_item_set, hf_index, ett_ansi_map_TriggerAddressList_item);

  return offset;
}
static int dissect_TriggerAddressList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_TriggerAddressList_item(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_TriggerAddressList_item);
}


static const ber_sequence_t TriggerAddressList_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_TriggerAddressList_item },
};

static int
dissect_ansi_map_TriggerAddressList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 TriggerAddressList_set_of, hf_index, ett_ansi_map_TriggerAddressList);

  return offset;
}
static int dissect_triggerAddressList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_TriggerAddressList(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_triggerAddressList);
}


static const ber_sequence_t FeatureRequestRes_set[] = {
  { BER_CLASS_CON, 18, BER_FLAGS_IMPLTAG, dissect_featureResult_impl },
  { BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_accessDeniedReason_impl },
  { BER_CLASS_CON, 128, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_actionCode_impl },
  { BER_CLASS_CON, 130, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_announcementList_impl },
  { BER_CLASS_CON, 82, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyNumberString1_impl },
  { BER_CLASS_CON, 83, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyNumberString2_impl },
  { BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartySubaddress_impl },
  { BER_CLASS_CON, 86, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_carrierDigits_impl },
  { BER_CLASS_CON, 137, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_conferenceCallingIndicator_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_digits_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_digits_Destination_impl },
  { BER_CLASS_CON, 244, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_displayText_impl },
  { BER_CLASS_CON, 299, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_displayText2_impl },
  { BER_CLASS_CON, 140, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_AccountCodeDigits_impl },
  { BER_CLASS_CON, 141, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_AlternateBillingDigits_impl },
  { BER_CLASS_CON, 142, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_BillingDigits_impl },
  { BER_CLASS_CON, 88, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_RedirectionIndicator_impl },
  { BER_CLASS_CON, 163, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_groupInformation_impl },
  { BER_CLASS_CON, 93, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mobileDirectoryNumber_impl },
  { BER_CLASS_CON, 96, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_noAnswerTime_impl },
  { BER_CLASS_CON, 97, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_oneTimeFeatureIndicator_impl },
  { BER_CLASS_CON, 146, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pACAIndicator_impl },
  { BER_CLASS_CON, 168, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pilotNumber_impl },
  { BER_CLASS_CON, 147, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_preferredLanguageIndicator_impl },
  { BER_CLASS_CON, 100, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectingNumberDigits_impl },
  { BER_CLASS_CON, 101, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectingNumberString_impl },
  { BER_CLASS_CON, 102, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectingSubaddress_impl },
  { BER_CLASS_CON, 394, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_resumePIC_impl },
  { BER_CLASS_CON, 150, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_routingDigits_impl },
  { BER_CLASS_CON, 120, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_terminationList_impl },
  { BER_CLASS_CON, 122, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_terminationTriggers_impl },
  { BER_CLASS_CON, 276, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_triggerAddressList_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_FeatureRequestRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              FeatureRequestRes_set, hf_index, ett_ansi_map_FeatureRequestRes);

  return offset;
}
static int dissect_featureRequestRes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_FeatureRequestRes(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_featureRequestRes);
}


static const ber_sequence_t FlashRequest_set[] = {
  { BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_digits_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_interMSCCircuitID_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_mobileIdentificationNumber_impl },
  { BER_CLASS_CON, 39, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_confidentialityModes_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_electronicSerialNumber_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_FlashRequest(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              FlashRequest_set, hf_index, ett_ansi_map_FlashRequest);

  return offset;
}
static int dissect_flashRequest(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_FlashRequest(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_flashRequest);
}


static const ber_sequence_t HandoffBack_set[] = {
  { BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_channelData_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_interMSCCircuitID_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_mobileIdentificationNumber_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_servingCellID_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_targetCellID_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_billingID_impl },
  { BER_CLASS_CON, 39, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_confidentialityModes_impl },
  { BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_handoffReason_impl },
  { BER_CLASS_CON, 164, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_handoffState_impl },
  { BER_CLASS_CON, 45, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_signalingMessageEncryptionKey_impl },
  { BER_CLASS_CON, 31, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tdmaBurstIndicator_impl },
  { BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tdmaCallMode_impl },
  { BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tdmaChannelData_impl },
  { BER_CLASS_CON, 48, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_voicePrivacyMask_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_HandoffBack(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              HandoffBack_set, hf_index, ett_ansi_map_HandoffBack);

  return offset;
}
static int dissect_handoffBack(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_HandoffBack(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_handoffBack);
}


static const ber_sequence_t HandoffBackRes_set[] = {
  { BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_channelData_impl },
  { BER_CLASS_CON, 39, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_confidentialityModes_impl },
  { BER_CLASS_CON, 31, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tdmaBurstIndicator_impl },
  { BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tdmaChannelData_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_HandoffBackRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              HandoffBackRes_set, hf_index, ett_ansi_map_HandoffBackRes);

  return offset;
}
static int dissect_handoffBackRes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_HandoffBackRes(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_handoffBackRes);
}


static const ber_sequence_t HandoffBack2_set[] = {
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_billingID_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_interMSCCircuitID_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_mobileIdentificationNumber_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_servingCellID_impl },
  { BER_CLASS_CON, 197, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_baseStationManufacturerCode_impl },
  { BER_CLASS_CON, 356, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdma2000HandoffInvokeIOSData_impl },
  { BER_CLASS_CON, 62, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaCallMode_impl },
  { BER_CLASS_CON, 63, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaChannelData_impl },
  { BER_CLASS_CON, 212, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaConnectionReferenceList_impl },
  { BER_CLASS_CON, 351, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaMSMeasuredChannelIdentity_impl },
  { BER_CLASS_CON, 66, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaMobileProtocolRevision_impl },
  { BER_CLASS_CON, 174, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaServiceConfigurationRecord_impl },
  { BER_CLASS_CON, 176, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaServiceOptionList_impl },
  { BER_CLASS_CON, 67, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaPrivateLongCodeMask_impl },
  { BER_CLASS_CON, 60, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaServingOneWayDelay_impl },
  { BER_CLASS_CON, 59, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaStationClassMark_impl },
  { BER_CLASS_CON, 177, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaStationClassMark2_impl },
  { BER_CLASS_CON, 136, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaTargetMAHOList_impl },
  { BER_CLASS_CON, 134, BER_FLAGS_IMPLTAG, dissect_cdmaTargetMeasurementList_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_channelData_impl },
  { BER_CLASS_CON, 39, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_confidentialityModes_impl },
  { BER_CLASS_CON, 215, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dataKey_impl },
  { BER_CLASS_CON, 216, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dataPrivacyParameters_impl },
  { BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_handoffReason_impl },
  { BER_CLASS_CON, 164, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_handoffState_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_interSwitchCount_impl },
  { BER_CLASS_CON, 217, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ilspInformation_impl },
  { BER_CLASS_CON, 70, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_msLocation_impl },
  { BER_CLASS_CON, 165, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_nampsCallMode_impl },
  { BER_CLASS_CON, 74, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_nampsChannelData_impl },
  { BER_CLASS_CON, 349, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pdsnAddress_impl },
  { BER_CLASS_CON, 350, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pdsnProtocolType_impl },
  { BER_CLASS_CON, 348, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_qosPriority_impl },
  { BER_CLASS_CON, 40, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_randomVariable_impl },
  { BER_CLASS_CON, 45, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_signalingMessageEncryptionKey_impl },
  { BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_stationClassMark_impl },
  { BER_CLASS_CON, 206, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_systemOperatorCode_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_targetCellID_impl },
  { BER_CLASS_CON, 220, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tdmaBandwidth_impl },
  { BER_CLASS_CON, 31, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tdmaBurstIndicator_impl },
  { BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tdmaCallMode_impl },
  { BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tdmaChannelData_impl },
  { BER_CLASS_CON, 178, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tdmaServiceCode_impl },
  { BER_CLASS_CON, 179, BER_FLAGS_OPTIONAL, dissect_tdmaTerminalCapability },
  { BER_CLASS_CON, 180, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tdmaVoiceCoder_impl },
  { BER_CLASS_CON, 47, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_terminalType_impl },
  { BER_CLASS_CON, 48, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_voicePrivacyMask_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_HandoffBack2(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              HandoffBack2_set, hf_index, ett_ansi_map_HandoffBack2);

  return offset;
}
static int dissect_handoffBack2(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_HandoffBack2(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_handoffBack2);
}


static const ber_sequence_t HandoffBack2Res_set[] = {
  { BER_CLASS_CON, 198, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_bsmcstatus_impl },
  { BER_CLASS_CON, 357, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdma2000HandoffResponseIOSData_impl },
  { BER_CLASS_CON, 63, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaChannelData_impl },
  { BER_CLASS_CON, 132, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaCodeChannelList_impl },
  { BER_CLASS_CON, 230, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaSearchParameters_impl },
  { BER_CLASS_CON, 212, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaConnectionReferenceList_impl },
  { BER_CLASS_CON, 69, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaSearchWindow_impl },
  { BER_CLASS_CON, 174, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaServiceConfigurationRecord_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_channelData_impl },
  { BER_CLASS_CON, 39, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_confidentialityModes_impl },
  { BER_CLASS_CON, 74, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_nampsChannelData_impl },
  { BER_CLASS_CON, 205, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sOCStatus_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_targetCellID_impl },
  { BER_CLASS_CON, 31, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tdmaBurstIndicator_impl },
  { BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tdmaChannelData_impl },
  { BER_CLASS_CON, 180, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tdmaVoiceCoder_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_HandoffBack2Res(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              HandoffBack2Res_set, hf_index, ett_ansi_map_HandoffBack2Res);

  return offset;
}
static int dissect_handoffBack2Res(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_HandoffBack2Res(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_handoffBack2Res);
}


static const ber_sequence_t TargetCellIDList_sequence[] = {
  { BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_targetCellID_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_targetCellID1_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_TargetCellIDList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   TargetCellIDList_sequence, hf_index, ett_ansi_map_TargetCellIDList);

  return offset;
}
static int dissect_targetCellIDList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_TargetCellIDList(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_targetCellIDList);
}


static const ber_sequence_t HandoffMeasurementRequest_set[] = {
  { BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_channelData_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_servingCellID_impl },
  { BER_CLASS_CON, 18, BER_FLAGS_IMPLTAG, dissect_stationClassMark_impl },
  { BER_CLASS_CON, 207, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_targetCellIDList_impl },
  { BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tdmaCallMode_impl },
  { BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tdmaChannelData_impl },
  { BER_CLASS_CON, 179, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tdmaTerminalCapability_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_HandoffMeasurementRequest(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              HandoffMeasurementRequest_set, hf_index, ett_ansi_map_HandoffMeasurementRequest);

  return offset;
}
static int dissect_handoffMeasurementRequest(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_HandoffMeasurementRequest(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_handoffMeasurementRequest);
}


static const value_string ansi_map_SignalQuality_vals[] = {
  {   0, "not-a-usable-signal" },
  {   1, "treat-as-Not-a-usable-signal" },
  {   2, "treat-as-Not-a-usable-signal" },
  {   3, "treat-as-Not-a-usable-signal" },
  {   4, "treat-as-Not-a-usable-signal" },
  {   5, "treat-as-Not-a-usable-signal" },
  {   6, "treat-as-Not-a-usable-signal" },
  {   7, "treat-as-Not-a-usable-signal" },
  {   8, "treat-as-Not-a-usable-signal" },
  {   9, "usable-signal-range" },
  { 245, "usable-signal-range" },
  { 246, "treat-the-same-as-interference" },
  { 247, "treat-the-same-as-interference" },
  { 248, "treat-the-same-as-interference" },
  { 249, "treat-the-same-as-interference" },
  { 250, "treat-the-same-as-interference" },
  { 251, "treat-the-same-as-interference" },
  { 252, "treat-the-same-as-interference" },
  { 253, "treat-the-same-as-interference" },
  { 254, "treat-the-same-as-interference" },
  { 255, "interference" },
  { 0, NULL }
};


static int
dissect_ansi_map_SignalQuality(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_signalQuality_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_SignalQuality(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_signalQuality);
}


static const ber_sequence_t HandoffMeasurementRequestRes_set[] = {
  { BER_CLASS_CON, 11, BER_FLAGS_IMPLTAG, dissect_signalQuality_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_targetCellID_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_HandoffMeasurementRequestRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              HandoffMeasurementRequestRes_set, hf_index, ett_ansi_map_HandoffMeasurementRequestRes);

  return offset;
}
static int dissect_handoffMeasurementRequestRes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_HandoffMeasurementRequestRes(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_handoffMeasurementRequestRes);
}


static const ber_sequence_t HandoffMeasurementRequest2_set[] = {
  { BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_servingCellID_impl },
  { BER_CLASS_CON, 62, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaCallMode_impl },
  { BER_CLASS_CON, 63, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaChannelData_impl },
  { BER_CLASS_CON, 174, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaServiceConfigurationRecord_impl },
  { BER_CLASS_CON, 60, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaServingOneWayDelay_impl },
  { BER_CLASS_CON, 59, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaStationClassMark_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_channelData_impl },
  { BER_CLASS_CON, 70, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_msLocation_impl },
  { BER_CLASS_CON, 165, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_nampsCallMode_impl },
  { BER_CLASS_CON, 74, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_nampsChannelData_impl },
  { BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_stationClassMark_impl },
  { BER_CLASS_CON, 207, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_targetCellIDList_impl },
  { BER_CLASS_CON, 220, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tdmaBandwidth_impl },
  { BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tdmaCallMode_impl },
  { BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tdmaChannelData_impl },
  { BER_CLASS_CON, 178, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tdmaServiceCode_impl },
  { BER_CLASS_CON, 179, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tdmaTerminalCapability_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_HandoffMeasurementRequest2(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              HandoffMeasurementRequest2_set, hf_index, ett_ansi_map_HandoffMeasurementRequest2);

  return offset;
}
static int dissect_handoffMeasurementRequest2(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_HandoffMeasurementRequest2(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_handoffMeasurementRequest2);
}


static const ber_sequence_t TargetMeasurementInformation_sequence[] = {
  { BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_targetCellID_impl },
  { BER_CLASS_CON, 11, BER_FLAGS_IMPLTAG, dissect_signalQuality_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_TargetMeasurementInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   TargetMeasurementInformation_sequence, hf_index, ett_ansi_map_TargetMeasurementInformation);

  return offset;
}
static int dissect_TargetMeasurementList_item_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_TargetMeasurementInformation(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_TargetMeasurementList_item);
}


static const ber_sequence_t TargetMeasurementList_sequence_of[1] = {
  { BER_CLASS_CON, 157, BER_FLAGS_IMPLTAG, dissect_TargetMeasurementList_item_impl },
};

static int
dissect_ansi_map_TargetMeasurementList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      TargetMeasurementList_sequence_of, hf_index, ett_ansi_map_TargetMeasurementList);

  return offset;
}
static int dissect_targetMeasurementList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_TargetMeasurementList(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_targetMeasurementList);
}


static const ber_sequence_t HandoffMeasurementRequest2Res_set[] = {
  { BER_CLASS_CON, 134, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaTargetMeasurementList_impl },
  { BER_CLASS_CON, 157, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_targetMeasurementList_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_HandoffMeasurementRequest2Res(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              HandoffMeasurementRequest2Res_set, hf_index, ett_ansi_map_HandoffMeasurementRequest2Res);

  return offset;
}
static int dissect_handoffMeasurementRequest2Res(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_HandoffMeasurementRequest2Res(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_handoffMeasurementRequest2Res);
}


static const ber_sequence_t HandoffToThird_set[] = {
  { BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_electronicSerialNumber_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_interMSCCircuitID_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_interSwitchCount_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_mobileIdentificationNumber_impl },
  { BER_CLASS_CON, 21, BER_FLAGS_IMPLTAG, dissect_mscid_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_servingCellID_impl },
  { BER_CLASS_CON, 197, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_baseStationManufacturerCode_impl },
  { BER_CLASS_CON, 18, BER_FLAGS_IMPLTAG, dissect_stationClassMark_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_targetCellID_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_billingID_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_channelData_impl },
  { BER_CLASS_CON, 39, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_confidentialityModes_impl },
  { BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_handoffReason_impl },
  { BER_CLASS_CON, 164, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_handoffState_impl },
  { BER_CLASS_CON, 45, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_signalingMessageEncryptionKey_impl },
  { BER_CLASS_CON, 31, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tdmaBurstIndicator_impl },
  { BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tdmaCallMode_impl },
  { BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tdmaChannelData_impl },
  { BER_CLASS_CON, 178, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tdmaServiceCode_impl },
  { BER_CLASS_CON, 179, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tdmaTerminalCapability_impl },
  { BER_CLASS_CON, 180, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tdmaVoiceCoder_impl },
  { BER_CLASS_CON, 47, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_terminalType_impl },
  { BER_CLASS_CON, 48, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_voicePrivacyMask_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_HandoffToThird(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              HandoffToThird_set, hf_index, ett_ansi_map_HandoffToThird);

  return offset;
}
static int dissect_handoffToThird(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_HandoffToThird(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_handoffToThird);
}


static const ber_sequence_t HandoffToThirdRes_set[] = {
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_channelData_impl },
  { BER_CLASS_CON, 39, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_confidentialityModes_impl },
  { BER_CLASS_CON, 31, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tdmaBurstIndicator_impl },
  { BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tdmaChannelData_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_HandoffToThirdRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              HandoffToThirdRes_set, hf_index, ett_ansi_map_HandoffToThirdRes);

  return offset;
}
static int dissect_handoffToThirdRes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_HandoffToThirdRes(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_handoffToThirdRes);
}


static const ber_sequence_t HandoffToThird2_set[] = {
  { BER_CLASS_CON, 198, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_bsmcstatus_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_billingID_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_electronicSerialNumber_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_interMSCCircuitID_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_interSwitchCount_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_mobileIdentificationNumber_impl },
  { BER_CLASS_CON, 21, BER_FLAGS_IMPLTAG, dissect_mscid_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_servingCellID_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_targetCellID_impl },
  { BER_CLASS_CON, 356, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdma2000HandoffInvokeIOSData_impl },
  { BER_CLASS_CON, 62, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaCallMode_impl },
  { BER_CLASS_CON, 63, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaChannelData_impl },
  { BER_CLASS_CON, 212, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaConnectionReferenceList_impl },
  { BER_CLASS_CON, 351, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaMSMeasuredChannelIdentity_impl },
  { BER_CLASS_CON, 66, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaMobileProtocolRevision_impl },
  { BER_CLASS_CON, 67, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaPrivateLongCodeMask_impl },
  { BER_CLASS_CON, 174, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaServiceConfigurationRecord_impl },
  { BER_CLASS_CON, 176, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaServiceOptionList_impl },
  { BER_CLASS_CON, 60, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaServingOneWayDelay_impl },
  { BER_CLASS_CON, 59, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaStationClassMark_impl },
  { BER_CLASS_CON, 177, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaStationClassMark2_impl },
  { BER_CLASS_CON, 136, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaTargetMAHOList_impl },
  { BER_CLASS_CON, 134, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaTargetMeasurementList_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_channelData_impl },
  { BER_CLASS_CON, 39, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_confidentialityModes_impl },
  { BER_CLASS_CON, 215, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dataKey_impl },
  { BER_CLASS_CON, 216, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dataPrivacyParameters_impl },
  { BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_handoffReason_impl },
  { BER_CLASS_CON, 217, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ilspInformation_impl },
  { BER_CLASS_CON, 70, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_msLocation_impl },
  { BER_CLASS_CON, 165, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_nampsCallMode_impl },
  { BER_CLASS_CON, 74, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_nampsChannelData_impl },
  { BER_CLASS_CON, 349, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pdsnAddress_impl },
  { BER_CLASS_CON, 350, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pdsnProtocolType_impl },
  { BER_CLASS_CON, 348, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_qosPriority_impl },
  { BER_CLASS_CON, 40, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_randomVariable_impl },
  { BER_CLASS_CON, 205, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sOCStatus_impl },
  { BER_CLASS_CON, 45, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_signalingMessageEncryptionKey_impl },
  { BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_stationClassMark_impl },
  { BER_CLASS_CON, 220, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tdmaBandwidth_impl },
  { BER_CLASS_CON, 31, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tdmaBurstIndicator_impl },
  { BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tdmaCallMode_impl },
  { BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tdmaChannelData_impl },
  { BER_CLASS_CON, 178, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tdmaServiceCode_impl },
  { BER_CLASS_CON, 179, BER_FLAGS_OPTIONAL, dissect_tdmaTerminalCapability },
  { BER_CLASS_CON, 180, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tdmaVoiceCoder_impl },
  { BER_CLASS_CON, 209, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_userZoneData_impl },
  { BER_CLASS_CON, 48, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_voicePrivacyMask_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_HandoffToThird2(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              HandoffToThird2_set, hf_index, ett_ansi_map_HandoffToThird2);

  return offset;
}
static int dissect_handoffToThird2(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_HandoffToThird2(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_handoffToThird2);
}


static const ber_sequence_t HandoffToThird2Res_set[] = {
  { BER_CLASS_CON, 357, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdma2000HandoffResponseIOSData_impl },
  { BER_CLASS_CON, 63, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaChannelData_impl },
  { BER_CLASS_CON, 132, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaCodeChannelList_impl },
  { BER_CLASS_CON, 212, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaConnectionReferenceList_impl },
  { BER_CLASS_CON, 230, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaSearchParameters_impl },
  { BER_CLASS_CON, 69, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaSearchWindow_impl },
  { BER_CLASS_CON, 174, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaServiceConfigurationRecord_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_channelData_impl },
  { BER_CLASS_CON, 39, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_confidentialityModes_impl },
  { BER_CLASS_CON, 74, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_nampsChannelData_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_targetCellID_impl },
  { BER_CLASS_CON, 31, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tdmaBurstIndicator_impl },
  { BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tdmaChannelData_impl },
  { BER_CLASS_CON, 180, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tdmaVoiceCoder_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_HandoffToThird2Res(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              HandoffToThird2Res_set, hf_index, ett_ansi_map_HandoffToThird2Res);

  return offset;
}
static int dissect_handoffToThird2Res(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_HandoffToThird2Res(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_handoffToThird2Res);
}


static const ber_sequence_t InformationDirective_set[] = {
  { BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_electronicSerialNumber_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_mobileIdentificationNumber_impl },
  { BER_CLASS_CON, 75, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_alertCode_impl },
  { BER_CLASS_CON, 130, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_announcementList_impl },
  { BER_CLASS_CON, 82, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyNumberString1_impl },
  { BER_CLASS_CON, 83, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyNumberString2_impl },
  { BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartySubaddress_impl },
  { BER_CLASS_CON, 244, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_displayText_impl },
  { BER_CLASS_CON, 299, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_displayText2_impl },
  { BER_CLASS_CON, 101, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectingNumberString_impl },
  { BER_CLASS_CON, 102, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectingSubaddress_impl },
  { BER_CLASS_CON, 103, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_senderIdentificationNumber_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_InformationDirective(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              InformationDirective_set, hf_index, ett_ansi_map_InformationDirective);

  return offset;
}
static int dissect_informationDirective(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_InformationDirective(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_informationDirective);
}



static int
dissect_ansi_map_AlertResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_alertResult_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_AlertResult(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_alertResult);
}


static const ber_sequence_t InformationDirectiveRes_set[] = {
  { BER_CLASS_CON, 129, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_alertResult_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_InformationDirectiveRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              InformationDirectiveRes_set, hf_index, ett_ansi_map_InformationDirectiveRes);

  return offset;
}



static int
dissect_ansi_map_MessageWaitingNotificationCount(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 230 "ansi_map.cnf"
	tvbuff_t *parameter_tvb = NULL;
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       &parameter_tvb);

	if (parameter_tvb){
		dissect_ansi_map_messagewaitingnotificationcount(parameter_tvb,pinfo,tree);
	}



  return offset;
}
static int dissect_messageWaitingNotificationCount_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_MessageWaitingNotificationCount(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_messageWaitingNotificationCount);
}



static int
dissect_ansi_map_MessageWaitingNotificationType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 238 "ansi_map.cnf"
	tvbuff_t *parameter_tvb = NULL;
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       &parameter_tvb);

	if (parameter_tvb){
		dissect_ansi_map_messagewaitingnotificationtype(parameter_tvb,pinfo,tree);
	}




  return offset;
}
static int dissect_messageWaitingNotificationType_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_MessageWaitingNotificationType(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_messageWaitingNotificationType);
}


static const ber_sequence_t InformationForward_set[] = {
  { BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_interMSCCircuitID_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_mobileIdentificationNumber_impl },
  { BER_CLASS_CON, 75, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_alertCode_impl },
  { BER_CLASS_CON, 130, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_announcementList_impl },
  { BER_CLASS_CON, 82, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyNumberString1_impl },
  { BER_CLASS_CON, 83, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyNumberString2_impl },
  { BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartySubaddress_impl },
  { BER_CLASS_CON, 244, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_displayText_impl },
  { BER_CLASS_CON, 299, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_displayText2_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_electronicSerialNumber_impl },
  { BER_CLASS_CON, 92, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_messageWaitingNotificationCount_impl },
  { BER_CLASS_CON, 289, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_messageWaitingNotificationType_impl },
  { BER_CLASS_CON, 101, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectingNumberString_impl },
  { BER_CLASS_CON, 102, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectingSubaddress_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_InformationForward(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              InformationForward_set, hf_index, ett_ansi_map_InformationForward);

  return offset;
}
static int dissect_informationForward(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_InformationForward(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_informationForward);
}


static const ber_sequence_t InformationForwardRes_set[] = {
  { BER_CLASS_CON, 129, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_alertResult_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_InformationForwardRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              InformationForwardRes_set, hf_index, ett_ansi_map_InformationForwardRes);

  return offset;
}
static int dissect_informationForwardRes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_InformationForwardRes(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_informationForwardRes);
}


static const ber_sequence_t InterSystemAnswer_set[] = {
  { BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_interMSCCircuitID_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_mobileIdentificationNumber_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_electronicSerialNumber_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_InterSystemAnswer(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              InterSystemAnswer_set, hf_index, ett_ansi_map_InterSystemAnswer);

  return offset;
}
static int dissect_interSystemAnswer(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_InterSystemAnswer(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_interSystemAnswer);
}



static int
dissect_ansi_map_CDMASlotCycleIndex(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_cdmaSlotCycleIndex_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_CDMASlotCycleIndex(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_cdmaSlotCycleIndex);
}



static int
dissect_ansi_map_ExtendedMSCID(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 199 "ansi_map.cnf"
	tvbuff_t *parameter_tvb = NULL;
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       &parameter_tvb);

	if (parameter_tvb){
		dissect_ansi_map_extendedmscid(parameter_tvb,pinfo,tree);
	}



  return offset;
}
static int dissect_extendedMSCID_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_ExtendedMSCID(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_extendedMSCID);
}



static int
dissect_ansi_map_ExtendedSystemMyTypeCode(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 207 "ansi_map.cnf"
	tvbuff_t *parameter_tvb = NULL;
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       &parameter_tvb);

	if (parameter_tvb){
		dissect_ansi_map_extendedsystemmytypecode(parameter_tvb,pinfo,tree);
	}


  return offset;
}
static int dissect_extendedSystemMyTypeCode_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_ExtendedSystemMyTypeCode(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_extendedSystemMyTypeCode);
}



static int
dissect_ansi_map_MSIDUsage(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_mSIDUsage_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_MSIDUsage(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_mSIDUsage);
}



static int
dissect_ansi_map_NetworkTMSI(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ansi_map_DigitsType(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_networkTMSI_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_NetworkTMSI(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_networkTMSI);
}



static int
dissect_ansi_map_PageCount(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_pageCount_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_PageCount(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_pageCount);
}



static int
dissect_ansi_map_PageIndicator(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_pageIndicator_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_PageIndicator(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_pageIndicator);
}



static int
dissect_ansi_map_PageResponseTime(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_pageResponseTime_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_PageResponseTime(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_pageResponseTime);
}



static int
dissect_ansi_map_PilotBillingID(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 311 "ansi_map.cnf"

	tvbuff_t *parameter_tvb = NULL;
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       &parameter_tvb);

	if (parameter_tvb){
		dissect_ansi_map_pilotbillingid(parameter_tvb,pinfo,tree);
	}



  return offset;
}
static int dissect_pilotBillingID_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_PilotBillingID(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_pilotBillingID);
}



static int
dissect_ansi_map_RedirectingPartyName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_redirectingPartyName_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_RedirectingPartyName(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_redirectingPartyName);
}


static const value_string ansi_map_SystemMyTypeCode_vals[] = {
  {   0, "not-used" },
  {   1, "eDS" },
  {   2, "astronet" },
  {   3, "lucent-Technologies" },
  {   4, "ericsson" },
  {   5, "gTE" },
  {   6, "motorola" },
  {   7, "nEC" },
  {   8, "nORTEL" },
  {   9, "novAtel" },
  {  10, "plexsys" },
  {  11, "digital-Equipment-Corp" },
  {  12, "iNET" },
  {  13, "bellcore" },
  {  14, "alcatel-SEL" },
  {  15, "compaq" },
  {  16, "qUALCOMM" },
  {  17, "aldiscon" },
  {  18, "celcore" },
  {  19, "tELOS" },
  {  20, "aDI-Limited" },
  {  21, "coral-Systems" },
  {  22, "synacom-Technology" },
  {  23, "dSC" },
  {  24, "mCI" },
  {  25, "newNet" },
  {  26, "sema-Group-Telecoms" },
  {  27, "lG-Information-and-Communications" },
  {  28, "cBIS" },
  {  29, "siemens" },
  {  30, "samsung-Electronics" },
  {  31, "readyCom-Inc" },
  {  32, "aG-Communication-Systems" },
  {  33, "hughes-Network-Systems" },
  {  34, "phoenix-Wireless-Group" },
  { 0, NULL }
};


static int
dissect_ansi_map_SystemMyTypeCode(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_systemMyTypeCode_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_SystemMyTypeCode(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_systemMyTypeCode);
}



static int
dissect_ansi_map_TDMADataFeaturesIndicator(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_tdmaDataFeaturesIndicator_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_TDMADataFeaturesIndicator(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_tdmaDataFeaturesIndicator);
}


static const ber_sequence_t InterSystemPage_set[] = {
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_billingID_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_electronicSerialNumber_impl },
  { BER_CLASS_CON, 75, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_alertCode_impl },
  { BER_CLASS_CON, 243, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyName_impl },
  { BER_CLASS_CON, 80, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyNumberDigits1_impl },
  { BER_CLASS_CON, 81, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyNumberDigits2_impl },
  { BER_CLASS_CON, 82, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyNumberString1_impl },
  { BER_CLASS_CON, 83, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyNumberString2_impl },
  { BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartySubaddress_impl },
  { BER_CLASS_CON, 170, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaBandClass_impl },
  { BER_CLASS_CON, 66, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaMobileProtocolRevision_impl },
  { BER_CLASS_CON, 175, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaServiceOption_impl },
  { BER_CLASS_CON, 176, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaServiceOptionList_impl },
  { BER_CLASS_CON, 166, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaSlotCycleIndex_impl },
  { BER_CLASS_CON, 59, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaStationClassMark_impl },
  { BER_CLASS_CON, 177, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaStationClassMark2_impl },
  { BER_CLASS_CON, 199, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_controlChannelMode_impl },
  { BER_CLASS_CON, 244, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_displayText_impl },
  { BER_CLASS_CON, 299, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_displayText2_impl },
  { BER_CLASS_CON, 140, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_AccountCodeDigits_impl },
  { BER_CLASS_CON, 141, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_AlternateBillingDigits_impl },
  { BER_CLASS_CON, 142, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_BillingDigits_impl },
  { BER_CLASS_CON, 53, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extendedMSCID_impl },
  { BER_CLASS_CON, 54, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extendedSystemMyTypeCode_impl },
  { BER_CLASS_CON, 242, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_imsi_impl },
  { BER_CLASS_CON, 288, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_legInformation_impl },
  { BER_CLASS_CON, 33, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_locationAreaID_impl },
  { BER_CLASS_CON, 93, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mobileDirectoryNumber_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mobileIdentificationNumber_impl },
  { BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mscid_impl },
  { BER_CLASS_CON, 94, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mSCIdentificationNumber_impl },
  { BER_CLASS_CON, 327, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mSIDUsage_impl },
  { BER_CLASS_CON, 233, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_networkTMSI_impl },
  { BER_CLASS_CON, 97, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_oneTimeFeatureIndicator_impl },
  { BER_CLASS_CON, 300, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pageCount_impl },
  { BER_CLASS_CON, 71, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pageIndicator_impl },
  { BER_CLASS_CON, 301, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pageResponseTime_impl },
  { BER_CLASS_CON, 32, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pc_ssn_impl },
  { BER_CLASS_CON, 169, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pilotBillingID_impl },
  { BER_CLASS_CON, 168, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pilotNumber_impl },
  { BER_CLASS_CON, 147, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_preferredLanguageIndicator_impl },
  { BER_CLASS_CON, 100, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectingNumberDigits_impl },
  { BER_CLASS_CON, 101, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectingNumberString_impl },
  { BER_CLASS_CON, 245, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectingPartyName_impl },
  { BER_CLASS_CON, 102, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectingSubaddress_impl },
  { BER_CLASS_CON, 103, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_senderIdentificationNumber_impl },
  { BER_CLASS_CON, 22, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_systemMyTypeCode_impl },
  { BER_CLASS_CON, 221, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tdmaDataFeaturesIndicator_impl },
  { BER_CLASS_CON, 178, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tdmaServiceCode_impl },
  { BER_CLASS_CON, 47, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_terminalType_impl },
  { BER_CLASS_CON, 121, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_terminationTreatment_impl },
  { BER_CLASS_CON, 122, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_terminationTriggers_impl },
  { BER_CLASS_CON, 276, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_triggerAddressList_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_InterSystemPage(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              InterSystemPage_set, hf_index, ett_ansi_map_InterSystemPage);

  return offset;
}
static int dissect_interSystemPage(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_InterSystemPage(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_interSystemPage);
}


static const value_string ansi_map_ConditionallyDeniedReason_vals[] = {
  {   0, "not-used" },
  {   1, "waitable" },
  { 0, NULL }
};


static int
dissect_ansi_map_ConditionallyDeniedReason(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_conditionallyDeniedReason_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_ConditionallyDeniedReason(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_conditionallyDeniedReason);
}


static const ber_sequence_t InterSystemPageRes_set[] = {
  { BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_accessDeniedReason_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_billingID_impl },
  { BER_CLASS_CON, 175, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaServiceOption_impl },
  { BER_CLASS_CON, 162, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_conditionallyDeniedReason_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_digits_impl },
  { BER_CLASS_CON, 53, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extendedMSCID_impl },
  { BER_CLASS_CON, 54, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extendedSystemMyTypeCode_impl },
  { BER_CLASS_CON, 94, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mSCIdentificationNumber_impl },
  { BER_CLASS_CON, 32, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pc_ssn_impl },
  { BER_CLASS_CON, 178, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tdmaServiceCode_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_InterSystemPageRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              InterSystemPageRes_set, hf_index, ett_ansi_map_InterSystemPageRes);

  return offset;
}
static int dissect_interSystemPageRes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_InterSystemPageRes(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_interSystemPageRes);
}



static int
dissect_ansi_map_PagingFrameClass(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_pagingFrameClass_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_PagingFrameClass(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_pagingFrameClass);
}



static int
dissect_ansi_map_PSID_RSIDInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_pSID_RSIDInformation_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_PSID_RSIDInformation(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_pSID_RSIDInformation);
}
static int dissect_pSID_RSIDInformation1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_PSID_RSIDInformation(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_pSID_RSIDInformation1);
}


static const ber_sequence_t PSID_RSIDList_sequence[] = {
  { BER_CLASS_CON, 202, BER_FLAGS_IMPLTAG, dissect_pSID_RSIDInformation_impl },
  { BER_CLASS_CON, 202, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pSID_RSIDInformation1_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_PSID_RSIDList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   PSID_RSIDList_sequence, hf_index, ett_ansi_map_PSID_RSIDList);

  return offset;
}
static int dissect_pSID_RSIDList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_PSID_RSIDList(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_pSID_RSIDList);
}


static const ber_sequence_t InterSystemPage2_set[] = {
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_billingID_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_electronicSerialNumber_impl },
  { BER_CLASS_CON, 75, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_alertCode_impl },
  { BER_CLASS_CON, 82, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyNumberString1_impl },
  { BER_CLASS_CON, 83, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyNumberString2_impl },
  { BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartySubaddress_impl },
  { BER_CLASS_CON, 170, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaBandClass_impl },
  { BER_CLASS_CON, 66, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaMobileProtocolRevision_impl },
  { BER_CLASS_CON, 199, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_controlChannelMode_impl },
  { BER_CLASS_CON, 175, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaServiceOption_impl },
  { BER_CLASS_CON, 176, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaServiceOptionList_impl },
  { BER_CLASS_CON, 166, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaSlotCycleIndex_impl },
  { BER_CLASS_CON, 59, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaStationClassMark_impl },
  { BER_CLASS_CON, 177, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaStationClassMark2_impl },
  { BER_CLASS_CON, 244, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_displayText_impl },
  { BER_CLASS_CON, 299, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_displayText2_impl },
  { BER_CLASS_CON, 242, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_imsi_impl },
  { BER_CLASS_CON, 33, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_locationAreaID_impl },
  { BER_CLASS_CON, 93, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mobileDirectoryNumber_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_mobileIdentificationNumber_impl },
  { BER_CLASS_CON, 327, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mSIDUsage_impl },
  { BER_CLASS_CON, 233, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_networkTMSI_impl },
  { BER_CLASS_CON, 200, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_nonPublicData_impl },
  { BER_CLASS_CON, 300, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pageCount_impl },
  { BER_CLASS_CON, 71, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pageIndicator_impl },
  { BER_CLASS_CON, 210, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pagingFrameClass_impl },
  { BER_CLASS_CON, 301, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pageResponseTime_impl },
  { BER_CLASS_CON, 203, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pSID_RSIDList_impl },
  { BER_CLASS_CON, 101, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectingNumberString_impl },
  { BER_CLASS_CON, 102, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectingSubaddress_impl },
  { BER_CLASS_CON, 221, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tdmaDataFeaturesIndicator_impl },
  { BER_CLASS_CON, 178, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tdmaServiceCode_impl },
  { BER_CLASS_CON, 47, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_terminalType_impl },
  { BER_CLASS_CON, 209, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_userZoneData_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_InterSystemPage2(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              InterSystemPage2_set, hf_index, ett_ansi_map_InterSystemPage2);

  return offset;
}
static int dissect_interSystemPage2(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_InterSystemPage2(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_interSystemPage2);
}



static int
dissect_ansi_map_RANDC(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_randc_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_RANDC(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_randc);
}



static int
dissect_ansi_map_TDMADataMode(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_tdmaDataMode_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_TDMADataMode(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_tdmaDataMode);
}


static const ber_sequence_t InterSystemPage2Res_set[] = {
  { BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_accessDeniedReason_impl },
  { BER_CLASS_CON, 36, BER_FLAGS_IMPLTAG, dissect_authenticationResponseBaseStation_impl },
  { BER_CLASS_CON, 38, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callHistoryCount_impl },
  { BER_CLASS_CON, 175, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaServiceOption_impl },
  { BER_CLASS_CON, 67, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_randc_impl },
  { BER_CLASS_CON, 41, BER_FLAGS_IMPLTAG, dissect_randomVariableBaseStation_impl },
  { BER_CLASS_CON, 34, BER_FLAGS_IMPLTAG, dissect_systemAccessType_impl },
  { BER_CLASS_CON, 49, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_systemCapabilities_impl },
  { BER_CLASS_CON, 222, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tdmaDataMode_impl },
  { BER_CLASS_CON, 178, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tdmaServiceCode_impl },
  { BER_CLASS_CON, 47, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_terminalType_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_InterSystemPage2Res(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              InterSystemPage2Res_set, hf_index, ett_ansi_map_InterSystemPage2Res);

  return offset;
}
static int dissect_interSystemPage2Res(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_InterSystemPage2Res(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_interSystemPage2Res);
}



static int
dissect_ansi_map_ChangeServiceAttributes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_changeServiceAttributes_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_ChangeServiceAttributes(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_changeServiceAttributes);
}


static const ber_sequence_t InterSystemSetup_set[] = {
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_billingID_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_electronicSerialNumber_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_interMSCCircuitID_impl },
  { BER_CLASS_CON, 75, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_alertCode_impl },
  { BER_CLASS_CON, 82, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyNumberString1_impl },
  { BER_CLASS_CON, 83, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyNumberString2_impl },
  { BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartySubaddress_impl },
  { BER_CLASS_CON, 67, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaPrivateLongCodeMask_impl },
  { BER_CLASS_CON, 175, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaServiceOption_impl },
  { BER_CLASS_CON, 176, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaServiceOptionList_impl },
  { BER_CLASS_CON, 214, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_changeServiceAttributes_impl },
  { BER_CLASS_CON, 215, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dataKey_impl },
  { BER_CLASS_CON, 244, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_displayText_impl },
  { BER_CLASS_CON, 299, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_displayText2_impl },
  { BER_CLASS_CON, 242, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_imsi_impl },
  { BER_CLASS_CON, 217, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ilspInformation_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_mobileIdentificationNumber_impl },
  { BER_CLASS_CON, 101, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectingNumberString_impl },
  { BER_CLASS_CON, 102, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_edirectingSubaddress_impl },
  { BER_CLASS_CON, 45, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_signalingMessageEncryptionKey_impl },
  { BER_CLASS_CON, 48, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_voicePrivacyMask_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_InterSystemSetup(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              InterSystemSetup_set, hf_index, ett_ansi_map_InterSystemSetup);

  return offset;
}
static int dissect_interSystemSetup(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_InterSystemSetup(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_interSystemSetup);
}



static int
dissect_ansi_map_SetupResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_setupResult_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_SetupResult(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_setupResult);
}


static const ber_sequence_t InterSystemSetupRes_set[] = {
  { BER_CLASS_CON, 212, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaConnectionReferenceList_impl },
  { BER_CLASS_CON, 175, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaServiceOption_impl },
  { BER_CLASS_CON, 217, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ilspInformation_impl },
  { BER_CLASS_CON, 151, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_setupResult_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_InterSystemSetupRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              InterSystemSetupRes_set, hf_index, ett_ansi_map_InterSystemSetupRes);

  return offset;
}
static int dissect_interSystemSetupRes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_InterSystemSetupRes(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_interSystemSetupRes);
}



static int
dissect_ansi_map_TerminationAccessType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_terminationAccessType_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_TerminationAccessType(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_terminationAccessType);
}



static int
dissect_ansi_map_TriggerCapability(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 412 "ansi_map.cnf"
	tvbuff_t *parameter_tvb = NULL;
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       &parameter_tvb);

	if (parameter_tvb){
		dissect_ansi_map_triggercapability(parameter_tvb,pinfo,tree);
	}



  return offset;
}
static int dissect_triggerCapability_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_TriggerCapability(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_triggerCapability);
}



static int
dissect_ansi_map_WINOperationsCapability(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 420 "ansi_map.cnf"
	tvbuff_t *parameter_tvb = NULL;
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       &parameter_tvb);

	if (parameter_tvb){
		dissect_ansi_map_winoperationscapability(parameter_tvb,pinfo,tree);
	}



  return offset;
}
static int dissect_wINOperationsCapability_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_WINOperationsCapability(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_wINOperationsCapability);
}


static const ber_sequence_t WINCapability_set[] = {
  { BER_CLASS_CON, 277, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_triggerCapability_impl },
  { BER_CLASS_CON, 281, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_wINOperationsCapability_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_WINCapability(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              WINCapability_set, hf_index, ett_ansi_map_WINCapability);

  return offset;
}
static int dissect_winCapability_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_WINCapability(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_winCapability);
}



static int
dissect_ansi_map_CallingPartyCategory(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_callingPartyCategory_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_CallingPartyCategory(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_callingPartyCategory);
}


static const ber_sequence_t LocationRequest_set[] = {
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_billingID_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_digits_impl },
  { BER_CLASS_CON, 21, BER_FLAGS_IMPLTAG, dissect_mscid_impl },
  { BER_CLASS_CON, 22, BER_FLAGS_IMPLTAG, dissect_systemMyTypeCode_impl },
  { BER_CLASS_CON, 340, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_acgencountered_impl },
  { BER_CLASS_CON, 80, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyNumberDigits1_impl },
  { BER_CLASS_CON, 81, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyNumberDigits2_impl },
  { BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartySubaddress_impl },
  { BER_CLASS_CON, 175, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaServiceOption_impl },
  { BER_CLASS_CON, 94, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mSCIdentificationNumber_impl },
  { BER_CLASS_CON, 32, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pc_ssn_impl },
  { BER_CLASS_CON, 100, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectingNumberDigits_impl },
  { BER_CLASS_CON, 245, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectingPartyName_impl },
  { BER_CLASS_CON, 102, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectingSubaddress_impl },
  { BER_CLASS_CON, 103, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_senderIdentificationNumber_impl },
  { BER_CLASS_CON, 119, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_terminationAccessType_impl },
  { BER_CLASS_CON, 178, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tdmaServiceCode_impl },
  { BER_CLASS_CON, 123, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_transactionCapability_impl },
  { BER_CLASS_CON, 279, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_triggerType_impl },
  { BER_CLASS_CON, 280, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_winCapability_impl },
  { BER_CLASS_CON, 355, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyCategory_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_LocationRequest(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              LocationRequest_set, hf_index, ett_ansi_map_LocationRequest);

  return offset;
}
static int dissect_locationRequest(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_LocationRequest(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_locationRequest);
}



static int
dissect_ansi_map_ControlNetworkID(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 428 "ansi_map.cnf"
	tvbuff_t *parameter_tvb = NULL;
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       &parameter_tvb);

	if (parameter_tvb){
		dissect_ansi_map_controlnetworkid(parameter_tvb,pinfo,tree);
	}



  return offset;
}
static int dissect_controlNetworkID_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_ControlNetworkID(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_controlNetworkID);
}



static int
dissect_ansi_map_DMH_ServiceID(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_dmh_ServiceID_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_DMH_ServiceID(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_dmh_ServiceID);
}


static const ber_sequence_t LocationRequestRes_set[] = {
  { BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_electronicSerialNumber_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_mobileIdentificationNumber_impl },
  { BER_CLASS_CON, 21, BER_FLAGS_IMPLTAG, dissect_mscid_impl },
  { BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_accessDeniedReason_impl },
  { BER_CLASS_CON, 130, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_announcementList_impl },
  { BER_CLASS_CON, 82, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyNumberString1_impl },
  { BER_CLASS_CON, 83, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyNumberString2_impl },
  { BER_CLASS_CON, 175, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaServiceOption_impl },
  { BER_CLASS_CON, 307, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_controlNetworkID_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_digits_carrier_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_digits_dest_impl },
  { BER_CLASS_CON, 244, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_displayText_impl },
  { BER_CLASS_CON, 299, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_displayText2_impl },
  { BER_CLASS_CON, 140, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_AccountCodeDigits_impl },
  { BER_CLASS_CON, 141, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_AlternateBillingDigits_impl },
  { BER_CLASS_CON, 142, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_BillingDigits_impl },
  { BER_CLASS_CON, 88, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_RedirectionIndicator_impl },
  { BER_CLASS_CON, 305, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_ServiceID_impl },
  { BER_CLASS_CON, 163, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_groupInformation_impl },
  { BER_CLASS_CON, 93, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mobileDirectoryNumber_impl },
  { BER_CLASS_CON, 96, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_noAnswerTime_impl },
  { BER_CLASS_CON, 97, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_oneTimeFeatureIndicator_impl },
  { BER_CLASS_CON, 32, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pc_ssn_impl },
  { BER_CLASS_CON, 147, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_preferredLanguageIndicator_impl },
  { BER_CLASS_CON, 100, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_edirectingNumberDigits_impl },
  { BER_CLASS_CON, 101, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectingNumberString_impl },
  { BER_CLASS_CON, 102, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectingSubaddress_impl },
  { BER_CLASS_CON, 150, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_routingDigits_impl },
  { BER_CLASS_CON, 178, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tdmaServiceCode_impl },
  { BER_CLASS_CON, 120, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_terminationList_impl },
  { BER_CLASS_CON, 122, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_terminationTriggers_impl },
  { BER_CLASS_CON, 276, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_triggerAddressList_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_LocationRequestRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              LocationRequestRes_set, hf_index, ett_ansi_map_LocationRequestRes);

  return offset;
}
static int dissect_locationRequestRes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_LocationRequestRes(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_locationRequestRes);
}


static const value_string ansi_map_DeregistrationType_vals[] = {
  {   0, "not-used" },
  {   1, "deregister-for-an-unspecified-reason" },
  {   2, "deregister-for-an-administrative-reason" },
  {   3, "deregister-due-to-MS-power-down" },
  { 0, NULL }
};


static int
dissect_ansi_map_DeregistrationType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_deregistrationType_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_DeregistrationType(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_deregistrationType);
}



static int
dissect_ansi_map_ServicesResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_servicesResult_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_ServicesResult(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_servicesResult);
}



static int
dissect_ansi_map_SMS_MessageWaitingIndicator(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_sms_MessageWaitingIndicator_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_SMS_MessageWaitingIndicator(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_sms_MessageWaitingIndicator);
}


static const ber_sequence_t MSInactive_set[] = {
  { BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_lectronicSerialNumber_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_mobileIdentificationNumber_impl },
  { BER_CLASS_CON, 38, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callHistoryCount_impl },
  { BER_CLASS_CON, 73, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_deregistrationType_impl },
  { BER_CLASS_CON, 87, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_destinationDigits_impl },
  { BER_CLASS_CON, 33, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_locationAreaID_impl },
  { BER_CLASS_CON, 103, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_senderIdentificationNumber_impl },
  { BER_CLASS_CON, 204, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_servicesResult_impl },
  { BER_CLASS_CON, 118, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sms_MessageWaitingIndicator_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_MSInactive(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              MSInactive_set, hf_index, ett_ansi_map_MSInactive);

  return offset;
}
static int dissect_mSInactive(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_MSInactive(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_mSInactive);
}



static int
dissect_ansi_map_OriginationTriggers(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 287 "ansi_map.cnf"
	tvbuff_t *parameter_tvb = NULL;
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       &parameter_tvb);

	if (parameter_tvb){
		dissect_ansi_map_originationtriggers(parameter_tvb,pinfo,tree);
	}



  return offset;
}
static int dissect_originationTriggers_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_OriginationTriggers(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_originationTriggers);
}


static const value_string ansi_map_FeatureIndicator_vals[] = {
  {   0, "not-used" },
  {  38, "user-selective-call-forwarding" },
  { 0, NULL }
};


static int
dissect_ansi_map_FeatureIndicator(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_featureIndicator_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_FeatureIndicator(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_featureIndicator);
}


static const ber_sequence_t OriginationRequest_set[] = {
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_billingID_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_digits_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_electronicSerialNumber_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_mobileIdentificationNumber_impl },
  { BER_CLASS_CON, 21, BER_FLAGS_IMPLTAG, dissect_mscid_impl },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_msid },
  { BER_CLASS_CON, 98, BER_FLAGS_IMPLTAG, dissect_originationTriggers_impl },
  { BER_CLASS_CON, 123, BER_FLAGS_IMPLTAG, dissect_transactionCapability_impl },
  { BER_CLASS_CON, 340, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_acgencountered_impl },
  { BER_CLASS_CON, 243, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyName_impl },
  { BER_CLASS_CON, 80, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyNumberDigits1_impl },
  { BER_CLASS_CON, 81, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyNumberDigits2_impl },
  { BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartySubaddress_impl },
  { BER_CLASS_CON, 175, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaServiceOption_impl },
  { BER_CLASS_CON, 33, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_locationAreaID_impl },
  { BER_CLASS_CON, 93, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mobileDirectoryNumber_impl },
  { BER_CLASS_CON, 306, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_featureIndicator_impl },
  { BER_CLASS_CON, 94, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mSCIdentificationNumber_impl },
  { BER_CLASS_CON, 97, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_oneTimeFeatureIndicator_impl },
  { BER_CLASS_CON, 32, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pc_ssn_impl },
  { BER_CLASS_CON, 147, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_preferredLanguageIndicator_impl },
  { BER_CLASS_CON, 103, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_senderIdentificationNumber_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_servingCellID_impl },
  { BER_CLASS_CON, 178, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tdmaServiceCode_impl },
  { BER_CLASS_CON, 279, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_triggerType_impl },
  { BER_CLASS_CON, 280, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_winCapability_impl },
  { BER_CLASS_CON, 355, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyCategory_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_OriginationRequest(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              OriginationRequest_set, hf_index, ett_ansi_map_OriginationRequest);

  return offset;
}
static int dissect_originationRequest(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_OriginationRequest(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_originationRequest);
}



static int
dissect_ansi_map_DMH_ChargeInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_dmh_ChargeInformation_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_DMH_ChargeInformation(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_dmh_ChargeInformation);
}


static const ber_sequence_t OriginationRequestRes_set[] = {
  { BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_accessDeniedReason_impl },
  { BER_CLASS_CON, 128, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_actionCode_impl },
  { BER_CLASS_CON, 130, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_announcementList_impl },
  { BER_CLASS_CON, 82, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyNumberString1_impl },
  { BER_CLASS_CON, 83, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyNumberString2_impl },
  { BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartySubaddress_impl },
  { BER_CLASS_CON, 86, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_carrierDigits_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_digits_impl },
  { BER_CLASS_CON, 244, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_displayText_impl },
  { BER_CLASS_CON, 299, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_displayText2_impl },
  { BER_CLASS_CON, 140, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_AccountCodeDigits_impl },
  { BER_CLASS_CON, 141, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_AlternateBillingDigits_impl },
  { BER_CLASS_CON, 142, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_BillingDigits_impl },
  { BER_CLASS_CON, 311, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_ChargeInformation_impl },
  { BER_CLASS_CON, 88, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_RedirectionIndicator_impl },
  { BER_CLASS_CON, 305, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_ServiceID_impl },
  { BER_CLASS_CON, 163, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_groupInformation_impl },
  { BER_CLASS_CON, 93, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mobileDirectoryNumber_impl },
  { BER_CLASS_CON, 96, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_noAnswerTime_impl },
  { BER_CLASS_CON, 97, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_oneTimeFeatureIndicator_impl },
  { BER_CLASS_CON, 168, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pilotNumber_impl },
  { BER_CLASS_CON, 147, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_preferredLanguageIndicator_impl },
  { BER_CLASS_CON, 100, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectingNumberDigits_impl },
  { BER_CLASS_CON, 101, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectingNumberString_impl },
  { BER_CLASS_CON, 102, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectingSubaddress_impl },
  { BER_CLASS_CON, 394, BER_FLAGS_IMPLTAG, dissect_resumePIC_impl },
  { BER_CLASS_CON, 150, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_routingDigits_impl },
  { BER_CLASS_CON, 120, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_terminationList_impl },
  { BER_CLASS_CON, 122, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_terminationTriggers_impl },
  { BER_CLASS_CON, 276, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_triggerAddressList_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_OriginationRequestRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              OriginationRequestRes_set, hf_index, ett_ansi_map_OriginationRequestRes);

  return offset;
}
static int dissect_originationRequestRes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_OriginationRequestRes(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_originationRequestRes);
}


static const value_string ansi_map_QualificationInformationCode_vals[] = {
  {   0, "not-used" },
  {   1, "no-information" },
  {   2, "validation-only" },
  {   3, "validation-and-profile" },
  {   4, "profile-only" },
  { 0, NULL }
};


static int
dissect_ansi_map_QualificationInformationCode(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_qualificationInformationCode_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_QualificationInformationCode(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_qualificationInformationCode);
}


static const value_string ansi_map_AuthorizationDenied_vals[] = {
  {   0, "not-used" },
  {   1, "delinquent-account" },
  {   2, "invalid-serial-number" },
  {   3, "stolen-unit" },
  {   4, "duplicate-unit" },
  {   5, "unassigned-directory-number" },
  {   6, "unspecified" },
  {   7, "multiple-access" },
  {   8, "not-Authorized-for-the-MSC" },
  {   9, "missing-authentication-parameters" },
  {  10, "terminalType-mismatch" },
  {  11, "requested-Service-Code-Not-Supported" },
  { 0, NULL }
};


static int
dissect_ansi_map_AuthorizationDenied(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_authorizationDenied_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_AuthorizationDenied(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_authorizationDenied);
}



static int
dissect_ansi_map_AuthorizationPeriod(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 128 "ansi_map.cnf"
	tvbuff_t *parameter_tvb = NULL;
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       &parameter_tvb);

	if (parameter_tvb){
		dissect_ansi_map_authorizationperiod(parameter_tvb,pinfo,tree);
	}




  return offset;
}
static int dissect_authorizationPeriod_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_AuthorizationPeriod(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_authorizationPeriod);
}



static int
dissect_ansi_map_DeniedAuthorizationPeriod(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 191 "ansi_map.cnf"
	tvbuff_t *parameter_tvb = NULL;
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       &parameter_tvb);

	if (parameter_tvb){
		dissect_ansi_map_deniedauthorizationperiod(parameter_tvb,pinfo,tree);
	}



  return offset;
}
static int dissect_deniedAuthorizationPeriod_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_DeniedAuthorizationPeriod(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_deniedAuthorizationPeriod);
}


static const ber_sequence_t QualificationDirective_set[] = {
  { BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_electronicSerialNumber_impl },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_msid },
  { BER_CLASS_CON, 17, BER_FLAGS_IMPLTAG, dissect_qualificationInformationCode_impl },
  { BER_CLASS_CON, 22, BER_FLAGS_IMPLTAG, dissect_systemMyTypeCode_impl },
  { BER_CLASS_CON, 225, BER_FLAGS_IMPLTAG, dissect_analogRedirectRecord_impl },
  { BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_authorizationDenied_impl },
  { BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_authorizationPeriod_impl },
  { BER_CLASS_CON, 229, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaRedirectRecord_impl },
  { BER_CLASS_CON, 199, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_controlChannelMode_impl },
  { BER_CLASS_CON, 167, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_deniedAuthorizationPeriod_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_digits_carrier_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_digits_dest_impl },
  { BER_CLASS_CON, 33, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_locationAreaID_impl },
  { BER_CLASS_CON, 238, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_serviceRedirectionInfo_impl },
  { BER_CLASS_CON, 239, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_roamingIndication_impl },
  { BER_CLASS_CON, 103, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_senderIdentificationNumber_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_QualificationDirective(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              QualificationDirective_set, hf_index, ett_ansi_map_QualificationDirective);

  return offset;
}
static int dissect_qualificationDirective(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_QualificationDirective(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_qualificationDirective);
}


static const ber_sequence_t QualificationRequest_set[] = {
  { BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_electronicSerialNumber_impl },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_msid },
  { BER_CLASS_CON, 17, BER_FLAGS_IMPLTAG, dissect_qualificationInformationCode_impl },
  { BER_CLASS_CON, 22, BER_FLAGS_IMPLTAG, dissect_systemMyTypeCode_impl },
  { BER_CLASS_CON, 33, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_locationAreaID_impl },
  { BER_CLASS_CON, 232, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaNetworkIdentification_impl },
  { BER_CLASS_CON, 199, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_controlChannelMode_impl },
  { BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mscid_impl },
  { BER_CLASS_CON, 103, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_senderIdentificationNumber_impl },
  { BER_CLASS_CON, 34, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_systemAccessType_impl },
  { BER_CLASS_CON, 47, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_terminalType_impl },
  { BER_CLASS_CON, 123, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_transactionCapability_impl },
  { BER_CLASS_CON, 280, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_winCapability_impl },
  { BER_CLASS_CON, 200, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_nonPublicData_impl },
  { BER_CLASS_CON, 209, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_userZoneData_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_QualificationRequest(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              QualificationRequest_set, hf_index, ett_ansi_map_QualificationRequest);

  return offset;
}
static int dissect_qualificationRequest(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_QualificationRequest(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_qualificationRequest);
}


static const ber_sequence_t QualificationRequestRes_set[] = {
  { BER_CLASS_CON, 22, BER_FLAGS_IMPLTAG, dissect_systemMyTypeCode_impl },
  { BER_CLASS_CON, 225, BER_FLAGS_IMPLTAG, dissect_analogRedirectRecord_impl },
  { BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_authorizationDenied_impl },
  { BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_authorizationPeriod_impl },
  { BER_CLASS_CON, 229, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaRedirectRecord_impl },
  { BER_CLASS_CON, 199, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_controlChannelMode_impl },
  { BER_CLASS_CON, 167, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_deniedAuthorizationPeriod_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_digits_carrier_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_digits_dest_impl },
  { BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mscid_impl },
  { BER_CLASS_CON, 238, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_serviceRedirectionInfo_impl },
  { BER_CLASS_CON, 239, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_roamingIndication_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_QualificationRequestRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              QualificationRequestRes_set, hf_index, ett_ansi_map_QualificationRequestRes);

  return offset;
}
static int dissect_qualificationRequestRes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_QualificationRequestRes(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_qualificationRequestRes);
}


static const ber_sequence_t RandomVariableRequest_set[] = {
  { BER_CLASS_CON, 21, BER_FLAGS_IMPLTAG, dissect_mscid_impl },
  { BER_CLASS_CON, 67, BER_FLAGS_IMPLTAG, dissect_randc_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_servingCellID_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_RandomVariableRequest(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              RandomVariableRequest_set, hf_index, ett_ansi_map_RandomVariableRequest);

  return offset;
}
static int dissect_randomVariableRequest(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_RandomVariableRequest(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_randomVariableRequest);
}



static int
dissect_ansi_map_RANDValidTime(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_randValidTime_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_RANDValidTime(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_randValidTime);
}


static const ber_sequence_t RandomVariableRequestRes_set[] = {
  { BER_CLASS_CON, 40, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_randomVariable_impl },
  { BER_CLASS_CON, 148, BER_FLAGS_IMPLTAG, dissect_randValidTime_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_RandomVariableRequestRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              RandomVariableRequestRes_set, hf_index, ett_ansi_map_RandomVariableRequestRes);

  return offset;
}
static int dissect_randomVariableRequestRes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_RandomVariableRequestRes(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_randomVariableRequestRes);
}


static const ber_sequence_t RedirectionDirective_set[] = {
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_billingID_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_digits_dest_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_electronicSerialNumber_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_mobileIdentificationNumber_impl },
  { BER_CLASS_CON, 22, BER_FLAGS_IMPLTAG, dissect_systemMyTypeCode_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_digits_carrier_impl },
  { BER_CLASS_CON, 140, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_AccountCodeDigits_impl },
  { BER_CLASS_CON, 141, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_AlternateBillingDigits_impl },
  { BER_CLASS_CON, 142, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_BillingDigits_impl },
  { BER_CLASS_CON, 94, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mSCIdentificationNumber_impl },
  { BER_CLASS_CON, 101, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectingNumberString_impl },
  { BER_CLASS_CON, 102, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectingSubaddress_impl },
  { BER_CLASS_CON, 103, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_senderIdentificationNumber_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_RedirectionDirective(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              RedirectionDirective_set, hf_index, ett_ansi_map_RedirectionDirective);

  return offset;
}
static int dissect_redirectionDirective(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_RedirectionDirective(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_redirectionDirective);
}


static const value_string ansi_map_RedirectionReason_vals[] = {
  {   0, "not-used" },
  {   1, "busy" },
  {   2, "no-Answer" },
  {   3, "unconditional" },
  {   4, "no-Page-Response" },
  {   5, "unavailable" },
  {   6, "unroutable" },
  {   7, "call-accepted" },
  {   8, "call-refused" },
  {   9, "uSCFvm-Divert-to-voice-mail" },
  {  10, "uSCFms-Divert-to-an-MS-provided-DN" },
  {  11, "uSCFnr-Divert-to-a-network-registered-DN" },
  { 0, NULL }
};


static int
dissect_ansi_map_RedirectionReason(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_redirectionReason_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_RedirectionReason(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_redirectionReason);
}


static const ber_sequence_t RedirectionRequest_set[] = {
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_billingID_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_electronicSerialNumber_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_mobileIdentificationNumber_impl },
  { BER_CLASS_CON, 19, BER_FLAGS_IMPLTAG, dissect_redirectionReason_impl },
  { BER_CLASS_CON, 175, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaServiceOption_impl },
  { BER_CLASS_CON, 288, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_legInformation_impl },
  { BER_CLASS_CON, 94, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mSCIdentificationNumber_impl },
  { BER_CLASS_CON, 178, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tdmaServiceCode_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_RedirectionRequest(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              RedirectionRequest_set, hf_index, ett_ansi_map_RedirectionRequest);

  return offset;
}
static int dissect_redirectionRequest(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_RedirectionRequest(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_redirectionRequest);
}



static int
dissect_ansi_map_CancellationType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_cancellationType_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_CancellationType(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_cancellationType);
}



static int
dissect_ansi_map_ControlChannelData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_controlChannelData_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_ControlChannelData(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_controlChannelData);
}



static int
dissect_ansi_map_ReceivedSignalQuality(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_receivedSignalQuality_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_ReceivedSignalQuality(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_receivedSignalQuality);
}



static int
dissect_ansi_map_SystemAccessData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_systemAccessData_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_SystemAccessData(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_systemAccessData);
}


static const ber_sequence_t RegistrationCancellation_set[] = {
  { BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_electronicSerialNumber_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_mobileIdentificationNumber_impl },
  { BER_CLASS_CON, 85, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cancellationType_impl },
  { BER_CLASS_CON, 55, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_controlChannelData_impl },
  { BER_CLASS_CON, 72, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_receivedSignalQuality_impl },
  { BER_CLASS_CON, 103, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_senderIdentificationNumber_impl },
  { BER_CLASS_CON, 56, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_systemAccessData_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_RegistrationCancellation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              RegistrationCancellation_set, hf_index, ett_ansi_map_RegistrationCancellation);

  return offset;
}
static int dissect_registrationCancellation(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_RegistrationCancellation(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_registrationCancellation);
}


static const value_string ansi_map_CancellationDenied_vals[] = {
  {   0, "not-used" },
  {   1, "multipleAccess" },
  {   2, "busy" },
  { 0, NULL }
};


static int
dissect_ansi_map_CancellationDenied(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_cancellationDenied_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_CancellationDenied(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_cancellationDenied);
}


static const ber_sequence_t RegistrationCancellationRes_set[] = {
  { BER_CLASS_CON, 38, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callHistoryCount_impl },
  { BER_CLASS_CON, 57, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cancellationDenied_impl },
  { BER_CLASS_CON, 55, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_controlChannelData_impl },
  { BER_CLASS_CON, 72, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_receivedSignalQuality_impl },
  { BER_CLASS_CON, 118, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sms_MessageWaitingIndicator_impl },
  { BER_CLASS_CON, 56, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_systemAccessData_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_RegistrationCancellationRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              RegistrationCancellationRes_set, hf_index, ett_ansi_map_RegistrationCancellationRes);

  return offset;
}
static int dissect_registrationCancellationRes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_RegistrationCancellationRes(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_registrationCancellationRes);
}



static int
dissect_ansi_map_AvailabilityType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_availabilityType_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_AvailabilityType(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_availabilityType);
}


static const value_string ansi_map_BorderCellAccess_vals[] = {
  {   0, "not-used" },
  {   1, "border-Cell-Access" },
  { 0, NULL }
};


static int
dissect_ansi_map_BorderCellAccess(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_borderCellAccess_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_BorderCellAccess(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_borderCellAccess);
}



static int
dissect_ansi_map_MSC_Address(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ansi_map_DigitsType(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_msc_Address_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_MSC_Address(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_msc_Address);
}



static int
dissect_ansi_map_SMS_Address(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ansi_map_DigitsType(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_sms_Address_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_SMS_Address(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_sms_Address);
}


static const ber_sequence_t RegistrationNotification_set[] = {
  { BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_electronicSerialNumber_impl },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_msid },
  { BER_CLASS_CON, 21, BER_FLAGS_IMPLTAG, dissect_mscid_impl },
  { BER_CLASS_CON, 17, BER_FLAGS_IMPLTAG, dissect_qualificationInformationCode_impl },
  { BER_CLASS_CON, 22, BER_FLAGS_IMPLTAG, dissect_systemMyTypeCode_impl },
  { BER_CLASS_CON, 90, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_availabilityType_impl },
  { BER_CLASS_CON, 50, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_borderCellAccess_impl },
  { BER_CLASS_CON, 232, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaNetworkIdentification_impl },
  { BER_CLASS_CON, 55, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_controlChannelData_impl },
  { BER_CLASS_CON, 199, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_controlChannelMode_impl },
  { BER_CLASS_CON, 53, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extendedMSCID_impl },
  { BER_CLASS_CON, 33, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_locationAreaID_impl },
  { BER_CLASS_CON, 284, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_msc_Address_impl },
  { BER_CLASS_CON, 32, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pc_ssn_impl },
  { BER_CLASS_CON, 72, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_receivedSignalQuality_impl },
  { BER_CLASS_CON, 44, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_reportType_impl },
  { BER_CLASS_CON, 237, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_serviceRedirectionCause_impl },
  { BER_CLASS_CON, 103, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_senderIdentificationNumber_impl },
  { BER_CLASS_CON, 104, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sms_Address_impl },
  { BER_CLASS_CON, 118, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sms_MessageWaitingIndicator_impl },
  { BER_CLASS_CON, 56, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_systemAccessData_impl },
  { BER_CLASS_CON, 34, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_systemAccessType_impl },
  { BER_CLASS_CON, 49, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_systemCapabilities_impl },
  { BER_CLASS_CON, 47, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_terminalType_impl },
  { BER_CLASS_CON, 123, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_transactionCapability_impl },
  { BER_CLASS_CON, 280, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_winCapability_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_RegistrationNotification(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              RegistrationNotification_set, hf_index, ett_ansi_map_RegistrationNotification);

  return offset;
}
static int dissect_registrationNotification(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_RegistrationNotification(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_registrationNotification);
}



static int
dissect_ansi_map_AuthenticationCapability(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_authenticationCapability_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_AuthenticationCapability(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_authenticationCapability);
}



static int
dissect_ansi_map_CallingFeaturesIndicator(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 145 "ansi_map.cnf"
	tvbuff_t *parameter_tvb = NULL;
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       &parameter_tvb);

	if (parameter_tvb){
		dissect_ansi_map_callingfeaturesindicator(parameter_tvb,pinfo,tree);
	}


  return offset;
}
static int dissect_callingFeaturesIndicator_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_CallingFeaturesIndicator(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_callingFeaturesIndicator);
}



static int
dissect_ansi_map_GeographicAuthorization(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_geographicAuthorization_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_GeographicAuthorization(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_geographicAuthorization);
}


static const value_string ansi_map_OriginationIndicator_vals[] = {
  {   0, "not-used" },
  {   1, "prior-agreement" },
  {   2, "origination-denied" },
  {   3, "local-calls-only" },
  {   4, "selected-leading-digits-of-directorynumberor-of-international-E164-number" },
  {   5, "selected-leading-digits-of-directorynumberor-of-international-E164-numbe-and-local-calls-only" },
  {   6, "national-long-distance" },
  {   7, "international-calls" },
  {   8, "single-directory-number-or-international-E164-number" },
  { 0, NULL }
};


static int
dissect_ansi_map_OriginationIndicator(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_originationIndicator_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_OriginationIndicator(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_originationIndicator);
}



static int
dissect_ansi_map_RestrictionDigits(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ansi_map_DigitsType(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_restrictionDigits_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_RestrictionDigits(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_restrictionDigits);
}



static int
dissect_ansi_map_SMS_OriginationRestrictions(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_sms_OriginationRestrictions_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_SMS_OriginationRestrictions(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_sms_OriginationRestrictions);
}



static int
dissect_ansi_map_SMS_TerminationRestrictions(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_sms_TerminationRestrictions_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_SMS_TerminationRestrictions(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_sms_TerminationRestrictions);
}



static int
dissect_ansi_map_SPINIPIN(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ansi_map_DigitsType(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_spinipin_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_SPINIPIN(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_spinipin);
}



static int
dissect_ansi_map_SPINITriggers(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_spiniTriggers_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_SPINITriggers(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_spiniTriggers);
}


static const value_string ansi_map_TerminationRestrictionCode_vals[] = {
  {   0, "not-used" },
  {   1, "termination-denied" },
  {   2, "unrestricted" },
  {   3, "the-treatment-for-this-value-is-not-specified" },
  { 0, NULL }
};


static int
dissect_ansi_map_TerminationRestrictionCode(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_terminationRestrictionCode_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_TerminationRestrictionCode(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_terminationRestrictionCode);
}


static const ber_sequence_t RegistrationNotificationRes_set[] = {
  { BER_CLASS_CON, 22, BER_FLAGS_IMPLTAG, dissect_systemMyTypeCode_impl },
  { BER_CLASS_CON, 225, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_analogRedirectRecord_impl },
  { BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_authorizationDenied_impl },
  { BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_authorizationPeriod_impl },
  { BER_CLASS_CON, 229, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaRedirectRecord_impl },
  { BER_CLASS_CON, 55, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_controlChannelData_impl },
  { BER_CLASS_CON, 167, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_deniedAuthorizationPeriod_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_digits_Carrier_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_digits_Destination_impl },
  { BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mscid_impl },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_msid },
  { BER_CLASS_CON, 78, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_authenticationCapability_impl },
  { BER_CLASS_CON, 25, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingFeaturesIndicator_impl },
  { BER_CLASS_CON, 86, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_carrierDigits_impl },
  { BER_CLASS_CON, 307, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_controlNetworkID_impl },
  { BER_CLASS_CON, 140, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_AccountCodeDigits_impl },
  { BER_CLASS_CON, 141, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_AlternateBillingDigits_impl },
  { BER_CLASS_CON, 142, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_BillingDigits_impl },
  { BER_CLASS_CON, 143, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_geographicAuthorization_impl },
  { BER_CLASS_CON, 92, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_messageWaitingNotificationCount_impl },
  { BER_CLASS_CON, 289, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_messageWaitingNotificationType_impl },
  { BER_CLASS_CON, 93, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mobileDirectoryNumber_impl },
  { BER_CLASS_CON, 23, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_originationIndicator_impl },
  { BER_CLASS_CON, 98, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_originationTriggers_impl },
  { BER_CLASS_CON, 146, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pACAIndicator_impl },
  { BER_CLASS_CON, 147, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_preferredLanguageIndicator_impl },
  { BER_CLASS_CON, 227, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_restrictionDigits_impl },
  { BER_CLASS_CON, 150, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_routingDigits_impl },
  { BER_CLASS_CON, 115, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sms_OriginationRestrictions_impl },
  { BER_CLASS_CON, 117, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sms_TerminationRestrictions_impl },
  { BER_CLASS_CON, 154, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_spinipin_impl },
  { BER_CLASS_CON, 155, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_spiniTriggers_impl },
  { BER_CLASS_CON, 24, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_terminationRestrictionCode_impl },
  { BER_CLASS_CON, 122, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_terminationTriggers_impl },
  { BER_CLASS_CON, 276, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_triggerAddressList_impl },
  { BER_CLASS_CON, 355, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyCategory_impl },
  { BER_CLASS_CON, 72, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_receivedSignalQuality_impl },
  { BER_CLASS_CON, 238, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_serviceRedirectionInfo_impl },
  { BER_CLASS_CON, 239, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_roamingIndication_impl },
  { BER_CLASS_CON, 103, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_senderIdentificationNumber_impl },
  { BER_CLASS_CON, 118, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sms_MessageWaitingIndicator_impl },
  { BER_CLASS_CON, 56, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_systemAccessData_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_RegistrationNotificationRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              RegistrationNotificationRes_set, hf_index, ett_ansi_map_RegistrationNotificationRes);

  return offset;
}
static int dissect_registrationNotificationRes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_RegistrationNotificationRes(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_registrationNotificationRes);
}



static int
dissect_ansi_map_DigitCollectionControl(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_digitCollectionControl_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_DigitCollectionControl(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_digitCollectionControl);
}


static const ber_sequence_t RemoteUserInteractionDirective_set[] = {
  { BER_CLASS_CON, 130, BER_FLAGS_IMPLTAG, dissect_announcementList_impl },
  { BER_CLASS_CON, 139, BER_FLAGS_IMPLTAG, dissect_digitCollectionControl_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_RemoteUserInteractionDirective(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              RemoteUserInteractionDirective_set, hf_index, ett_ansi_map_RemoteUserInteractionDirective);

  return offset;
}
static int dissect_remoteUserInteractionDirective(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_RemoteUserInteractionDirective(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_remoteUserInteractionDirective);
}


static const ber_sequence_t RemoteUserInteractionDirectiveRes_set[] = {
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_digits_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_RemoteUserInteractionDirectiveRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              RemoteUserInteractionDirectiveRes_set, hf_index, ett_ansi_map_RemoteUserInteractionDirectiveRes);

  return offset;
}
static int dissect_remoteUserInteractionDirectiveRes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_RemoteUserInteractionDirectiveRes(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_remoteUserInteractionDirectiveRes);
}


static const ber_sequence_t ResetCircuit_set[] = {
  { BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_interMSCCircuitID_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_ResetCircuit(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              ResetCircuit_set, hf_index, ett_ansi_map_ResetCircuit);

  return offset;
}
static int dissect_resetCircuit(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_ResetCircuit(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_resetCircuit);
}


static const value_string ansi_map_TrunkStatus_vals[] = {
  {   0, "idle" },
  {   1, "blocked" },
  { 0, NULL }
};


static int
dissect_ansi_map_TrunkStatus(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_trunkStatus_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_TrunkStatus(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_trunkStatus);
}


static const ber_sequence_t ResetCircuitRes_set[] = {
  { BER_CLASS_CON, 16, BER_FLAGS_IMPLTAG, dissect_trunkStatus_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_ResetCircuitRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              ResetCircuitRes_set, hf_index, ett_ansi_map_ResetCircuitRes);

  return offset;
}
static int dissect_resetCircuitRes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_ResetCircuitRes(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_resetCircuitRes);
}



static int
dissect_ansi_map_UserGroup(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_userGroup_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_UserGroup(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_userGroup);
}


static const ber_sequence_t RoutingRequest_set[] = {
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_billingID_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_electronicSerialNumber_impl },
  { BER_CLASS_CON, 21, BER_FLAGS_IMPLTAG, dissect_mscid_impl },
  { BER_CLASS_CON, 22, BER_FLAGS_IMPLTAG, dissect_systemMyTypeCode_impl },
  { BER_CLASS_CON, 75, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_alertCode_impl },
  { BER_CLASS_CON, 243, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyName_impl },
  { BER_CLASS_CON, 80, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyNumberDigits1_impl },
  { BER_CLASS_CON, 81, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyNumberDigits2_impl },
  { BER_CLASS_CON, 82, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyNumberString1_impl },
  { BER_CLASS_CON, 83, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyNumberString2_impl },
  { BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartySubaddress_impl },
  { BER_CLASS_CON, 175, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaServiceOption_impl },
  { BER_CLASS_CON, 199, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_controlChannelMode_impl },
  { BER_CLASS_CON, 87, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_destinationDigits_impl },
  { BER_CLASS_CON, 244, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_displayText_impl },
  { BER_CLASS_CON, 299, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_displayText2_impl },
  { BER_CLASS_CON, 140, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_AccountCodeDigits_impl },
  { BER_CLASS_CON, 141, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_AlternateBillingDigits_impl },
  { BER_CLASS_CON, 142, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_BillingDigits_impl },
  { BER_CLASS_CON, 288, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_legInformation_impl },
  { BER_CLASS_CON, 33, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_locationAreaID_impl },
  { BER_CLASS_CON, 93, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mobileDirectoryNumber_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_mobileIdentificationNumber_impl },
  { BER_CLASS_CON, 94, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mSCIdentificationNumber_impl },
  { BER_CLASS_CON, 96, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_noAnswerTime_impl },
  { BER_CLASS_CON, 97, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_oneTimeFeatureIndicator_impl },
  { BER_CLASS_CON, 32, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pc_ssn_impl },
  { BER_CLASS_CON, 169, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pilotBillingID_impl },
  { BER_CLASS_CON, 168, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pilotNumber_impl },
  { BER_CLASS_CON, 100, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectingNumberDigits_impl },
  { BER_CLASS_CON, 101, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectingNumberString_impl },
  { BER_CLASS_CON, 245, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectingPartyName_impl },
  { BER_CLASS_CON, 102, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectingSubaddress_impl },
  { BER_CLASS_CON, 103, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_senderIdentificationNumber_impl },
  { BER_CLASS_CON, 178, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tdmaServiceCode_impl },
  { BER_CLASS_CON, 121, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_terminationTreatment_impl },
  { BER_CLASS_CON, 122, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_terminationTriggers_impl },
  { BER_CLASS_CON, 276, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_triggerAddressList_impl },
  { BER_CLASS_CON, 208, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_userGroup_impl },
  { BER_CLASS_CON, 123, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_transactionCapability_impl },
  { BER_CLASS_CON, 160, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_voiceMailboxNumber_impl },
  { BER_CLASS_CON, 159, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_voiceMailboxPIN_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_RoutingRequest(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              RoutingRequest_set, hf_index, ett_ansi_map_RoutingRequest);

  return offset;
}
static int dissect_routingRequest(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_RoutingRequest(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_routingRequest);
}


static const ber_sequence_t RoutingRequestRes_set[] = {
  { BER_CLASS_CON, 21, BER_FLAGS_IMPLTAG, dissect_mscid_impl },
  { BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_accessDeniedReason_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_billingID_impl },
  { BER_CLASS_CON, 175, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaServiceOption_impl },
  { BER_CLASS_CON, 162, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_conditionallyDeniedReason_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_digits_Destination_impl },
  { BER_CLASS_CON, 94, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mSCIdentificationNumber_impl },
  { BER_CLASS_CON, 32, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pc_ssn_impl },
  { BER_CLASS_CON, 178, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tdmaServiceCode_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_RoutingRequestRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              RoutingRequestRes_set, hf_index, ett_ansi_map_RoutingRequestRes);

  return offset;
}
static int dissect_routingRequestRes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_RoutingRequestRes(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_routingRequestRes);
}



static int
dissect_ansi_map_SMS_BearerData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 320 "ansi_map.cnf"
	int length;
    proto_item *item;
    proto_tree *subtree;
	SMS_BearerData_tvb = NULL;

  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       &SMS_BearerData_tvb);

	if (SMS_BearerData_tvb){
		/* A zero length OCTET STRING will return a zero length tvb */
		length = tvb_length_remaining(SMS_BearerData_tvb,0);
		if (length <=0){
			item = get_ber_last_created_item();
			subtree = proto_item_add_subtree(item, ett_sms_bearer_data);
			proto_item_append_text(item," length %u",length);
			SMS_BearerData_tvb = NULL;
			return offset;
		}
	}



  return offset;
}
static int dissect_sms_BearerData_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_SMS_BearerData(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_sms_BearerData);
}



static int
dissect_ansi_map_SMS_TeleserviceIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 341 "ansi_map.cnf"

	int length;
    proto_item *item;
    proto_tree *subtree;
	tvbuff_t *parameter_tvb = NULL;
	static gint32 ansi_map_sms_tele_id = -1;

  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       &parameter_tvb);

	if (parameter_tvb){
		/* A zero length OCTET STRING will return a zero length tvb */
		length = tvb_length_remaining(parameter_tvb,0);
		if (length <=0){
			item = get_ber_last_created_item();
			subtree = proto_item_add_subtree(item, ett_sms_teleserviceIdentifier);
			proto_item_append_text(item, " length %u",length);
			return offset;
		}
		ansi_map_sms_tele_id = tvb_get_ntohs(tvb,0);
		if ((ansi_map_sms_tele_id != -1)&&(SMS_BearerData_tvb !=NULL))
		{
		    dissector_try_port(is637_tele_id_dissector_table, ansi_map_sms_tele_id, SMS_BearerData_tvb, g_pinfo, g_tree);
		}
	}



  return offset;
}
static int dissect_sms_TeleserviceIdentifier_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_SMS_TeleserviceIdentifier(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_sms_TeleserviceIdentifier);
}



static int
dissect_ansi_map_SMS_ChargeIndicator(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_sms_ChargeIndicator_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_SMS_ChargeIndicator(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_sms_ChargeIndicator);
}



static int
dissect_ansi_map_SMS_DestinationAddress(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ansi_map_DigitsType(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_sms_DestinationAddress_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_SMS_DestinationAddress(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_sms_DestinationAddress);
}



static int
dissect_ansi_map_SMS_OriginalDestinationAddress(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ansi_map_DigitsType(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_sms_OriginalDestinationAddress_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_SMS_OriginalDestinationAddress(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_sms_OriginalDestinationAddress);
}



static int
dissect_ansi_map_SMS_OriginalDestinationSubaddress(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ansi_map_Subaddress(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_sms_OriginalDestinationSubaddress_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_SMS_OriginalDestinationSubaddress(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_sms_OriginalDestinationSubaddress);
}



static int
dissect_ansi_map_SMS_OriginalOriginatingAddress(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ansi_map_DigitsType(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_sms_OriginalOriginatingAddress_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_SMS_OriginalOriginatingAddress(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_sms_OriginalOriginatingAddress);
}



static int
dissect_ansi_map_SMS_OriginalOriginatingSubaddress(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ansi_map_Subaddress(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_sms_OriginalOriginatingSubaddress_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_SMS_OriginalOriginatingSubaddress(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_sms_OriginalOriginatingSubaddress);
}



static int
dissect_ansi_map_SMS_OriginatingAddress(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ansi_map_DigitsType(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_sms_OriginatingAddress_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_SMS_OriginatingAddress(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_sms_OriginatingAddress);
}


static const ber_sequence_t SMSDeliveryBackward_set[] = {
  { BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_interMSCCircuitID_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_mobileIdentificationNumber_impl },
  { BER_CLASS_CON, 105, BER_FLAGS_IMPLTAG, dissect_sms_BearerData_impl },
  { BER_CLASS_CON, 116, BER_FLAGS_IMPLTAG, dissect_sms_TeleserviceIdentifier_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_electronicSerialNumber_impl },
  { BER_CLASS_CON, 106, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sms_ChargeIndicator_impl },
  { BER_CLASS_CON, 107, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sms_DestinationAddress_impl },
  { BER_CLASS_CON, 110, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sms_OriginalDestinationAddress_impl },
  { BER_CLASS_CON, 111, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sms_OriginalDestinationSubaddress_impl },
  { BER_CLASS_CON, 112, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sms_OriginalOriginatingAddress_impl },
  { BER_CLASS_CON, 113, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sms_OriginalOriginatingSubaddress_impl },
  { BER_CLASS_CON, 114, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sms_OriginatingAddress_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_SMSDeliveryBackward(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              SMSDeliveryBackward_set, hf_index, ett_ansi_map_SMSDeliveryBackward);

  return offset;
}
static int dissect_sMSDeliveryBackward(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_SMSDeliveryBackward(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_sMSDeliveryBackward);
}



static int
dissect_ansi_map_SMS_CauseCode(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_sms_CauseCode_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_SMS_CauseCode(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_sms_CauseCode);
}


static const ber_sequence_t SMSDeliveryBackwardRes_set[] = {
  { BER_CLASS_CON, 105, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sms_BearerData_impl },
  { BER_CLASS_CON, 153, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sms_CauseCode_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_SMSDeliveryBackwardRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              SMSDeliveryBackwardRes_set, hf_index, ett_ansi_map_SMSDeliveryBackwardRes);

  return offset;
}
static int dissect_sMSDeliveryBackwardRes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_SMSDeliveryBackwardRes(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_sMSDeliveryBackwardRes);
}


static const ber_sequence_t SMSDeliveryForward_set[] = {
  { BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_interMSCCircuitID_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_mobileIdentificationNumber_impl },
  { BER_CLASS_CON, 105, BER_FLAGS_IMPLTAG, dissect_sms_BearerData_impl },
  { BER_CLASS_CON, 116, BER_FLAGS_IMPLTAG, dissect_sms_TeleserviceIdentifier_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_electronicSerialNumber_impl },
  { BER_CLASS_CON, 106, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sms_ChargeIndicator_impl },
  { BER_CLASS_CON, 107, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sms_DestinationAddress_impl },
  { BER_CLASS_CON, 110, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sms_OriginalDestinationAddress_impl },
  { BER_CLASS_CON, 111, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sms_OriginalDestinationSubaddress_impl },
  { BER_CLASS_CON, 112, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sms_OriginalOriginatingAddress_impl },
  { BER_CLASS_CON, 113, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sms_OriginalOriginatingSubaddress_impl },
  { BER_CLASS_CON, 114, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sms_OriginatingAddress_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_SMSDeliveryForward(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              SMSDeliveryForward_set, hf_index, ett_ansi_map_SMSDeliveryForward);

  return offset;
}
static int dissect_sMSDeliveryForward(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_SMSDeliveryForward(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_sMSDeliveryForward);
}


static const ber_sequence_t SMSDeliveryForwardRes_set[] = {
  { BER_CLASS_CON, 105, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sms_BearerData_impl },
  { BER_CLASS_CON, 153, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sms_CauseCode_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_SMSDeliveryForwardRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              SMSDeliveryForwardRes_set, hf_index, ett_ansi_map_SMSDeliveryForwardRes);

  return offset;
}
static int dissect_sMSDeliveryForwardRes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_SMSDeliveryForwardRes(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_sMSDeliveryForwardRes);
}



static int
dissect_ansi_map_InterMessageTime(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_interMessageTime_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_InterMessageTime(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_interMessageTime);
}



static int
dissect_ansi_map_NewlyAssignedMIN(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ansi_map_MINType(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_newlyAssignedMIN_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_NewlyAssignedMIN(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_newlyAssignedMIN);
}



static int
dissect_ansi_map_IMSIType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_ansi_map_NewlyAssignedIMSI(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ansi_map_IMSIType(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_newlyAssignedIMSI_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_NewlyAssignedIMSI(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_newlyAssignedIMSI);
}



static int
dissect_ansi_map_NewMINExtension(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ansi_map_MINType(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_newMINExtension_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_NewMINExtension(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_newMINExtension);
}



static int
dissect_ansi_map_SMS_MessageCount(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_sms_MessageCount_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_SMS_MessageCount(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_sms_MessageCount);
}



static int
dissect_ansi_map_SMS_NotificationIndicator(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_sms_NotificationIndicator_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_SMS_NotificationIndicator(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_sms_NotificationIndicator);
}



static int
dissect_ansi_map_TemporaryReferenceNumber(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_temporaryReferenceNumber_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_TemporaryReferenceNumber(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_temporaryReferenceNumber);
}


static const ber_sequence_t SMSDeliveryPointToPoint_set[] = {
  { BER_CLASS_CON, 105, BER_FLAGS_IMPLTAG, dissect_sms_BearerData_impl },
  { BER_CLASS_CON, 116, BER_FLAGS_IMPLTAG, dissect_sms_TeleserviceIdentifier_impl },
  { BER_CLASS_CON, 128, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_actionCode_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_electronicSerialNumber_impl },
  { BER_CLASS_CON, 325, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_interMessageTime_impl },
  { BER_CLASS_CON, 242, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_imsi_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mobileIdentificationNumber_impl },
  { BER_CLASS_CON, 187, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_newlyAssignedMIN_impl },
  { BER_CLASS_CON, 287, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_newlyAssignedIMSI_impl },
  { BER_CLASS_CON, 328, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_newMINExtension_impl },
  { BER_CLASS_CON, 193, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_serviceIndicator_impl },
  { BER_CLASS_CON, 106, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sms_ChargeIndicator_impl },
  { BER_CLASS_CON, 107, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sms_DestinationAddress_impl },
  { BER_CLASS_CON, 108, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sms_MessageCount_impl },
  { BER_CLASS_CON, 109, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sms_NotificationIndicator_impl },
  { BER_CLASS_CON, 110, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sms_OriginalDestinationAddress_impl },
  { BER_CLASS_CON, 111, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sms_OriginalDestinationSubaddress_impl },
  { BER_CLASS_CON, 112, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sms_OriginalOriginatingAddress_impl },
  { BER_CLASS_CON, 113, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sms_OriginalOriginatingSubaddress_impl },
  { BER_CLASS_CON, 114, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sms_OriginatingAddress_impl },
  { BER_CLASS_CON, 195, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_temporaryReferenceNumber_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_SMSDeliveryPointToPoint(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              SMSDeliveryPointToPoint_set, hf_index, ett_ansi_map_SMSDeliveryPointToPoint);

  return offset;
}
static int dissect_sMSDeliveryPointToPoint(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_SMSDeliveryPointToPoint(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_sMSDeliveryPointToPoint);
}



static int
dissect_ansi_map_MobileStationIMSI(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ansi_map_IMSIType(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_mobileStationIMSI_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_MobileStationIMSI(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_mobileStationIMSI);
}


static const value_string ansi_map_MobileStationMSID_vals[] = {
  { 184, "mobileStationMIN" },
  { 286, "mobileStationIMSI" },
  { 0, NULL }
};

static const ber_choice_t MobileStationMSID_choice[] = {
  { 184, BER_CLASS_CON, 184, BER_FLAGS_IMPLTAG, dissect_mobileStationMIN_impl },
  { 286, BER_CLASS_CON, 286, BER_FLAGS_IMPLTAG, dissect_mobileStationIMSI_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_ansi_map_MobileStationMSID(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 MobileStationMSID_choice, hf_index, ett_ansi_map_MobileStationMSID,
                                 NULL);

  return offset;
}
static int dissect_mobileStationMSID(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_MobileStationMSID(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_mobileStationMSID);
}


static const ber_sequence_t SMSDeliveryPointToPointRes_set[] = {
  { BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_authorizationDenied_impl },
  { BER_CLASS_CON, 50, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_denyAccess_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_electronicSerialNumber_impl },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_mobileStationMSID },
  { BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mscid_impl },
  { BER_CLASS_CON, 105, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sms_BearerData_impl },
  { BER_CLASS_CON, 153, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sms_CauseCode_impl },
  { BER_CLASS_CON, 49, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_systemCapabilities_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_SMSDeliveryPointToPointRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              SMSDeliveryPointToPointRes_set, hf_index, ett_ansi_map_SMSDeliveryPointToPointRes);

  return offset;
}
static int dissect_sMSDeliveryPointToPointRes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_SMSDeliveryPointToPointRes(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_sMSDeliveryPointToPointRes);
}



static int
dissect_ansi_map_SMS_AccessDeniedReason(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_sms_AccessDeniedReason_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_SMS_AccessDeniedReason(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_sms_AccessDeniedReason);
}


static const ber_sequence_t SMSNotification_set[] = {
  { BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_electronicSerialNumber_impl },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_msid },
  { BER_CLASS_CON, 93, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mobileDirectoryNumber_impl },
  { BER_CLASS_CON, 152, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sms_AccessDeniedReason_impl },
  { BER_CLASS_CON, 104, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sms_Address_impl },
  { BER_CLASS_CON, 116, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sms_TeleserviceIdentifier_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_SMSNotification(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              SMSNotification_set, hf_index, ett_ansi_map_SMSNotification);

  return offset;
}
static int dissect_sMSNotification(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_SMSNotification(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_sMSNotification);
}


static const ber_sequence_t SMSNotificationRes_set[] = {
  { BER_CLASS_CON, 108, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sms_MessageCount_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_SMSNotificationRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              SMSNotificationRes_set, hf_index, ett_ansi_map_SMSNotificationRes);

  return offset;
}
static int dissect_sMSNotificationRes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_SMSNotificationRes(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_sMSNotificationRes);
}


static const ber_sequence_t SMSRequest_set[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_msid },
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_electronicSerialNumber_impl },
  { BER_CLASS_CON, 93, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mobileDirectoryNumber_impl },
  { BER_CLASS_CON, 193, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_serviceIndicator_impl },
  { BER_CLASS_CON, 109, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sms_NotificationIndicator_impl },
  { BER_CLASS_CON, 116, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sms_TeleserviceIdentifier_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_SMSRequest(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              SMSRequest_set, hf_index, ett_ansi_map_SMSRequest);

  return offset;
}
static int dissect_sMSRequest(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_SMSRequest(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_sMSRequest);
}


static const ber_sequence_t SMSRequestRes_set[] = {
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_electronicSerialNumber_impl },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_msid },
  { BER_CLASS_CON, 152, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sms_AccessDeniedReason_impl },
  { BER_CLASS_CON, 104, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sms_Address_impl },
  { BER_CLASS_CON, 153, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sms_CauseCode_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_SMSRequestRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              SMSRequestRes_set, hf_index, ett_ansi_map_SMSRequestRes);

  return offset;
}
static int dissect_sMSRequestRes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_SMSRequestRes(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_sMSRequestRes);
}


static const ber_sequence_t TransferToNumberRequest_set[] = {
  { BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_electronicSerialNumber_impl },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_msid },
  { BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_mobileIdentificationNumber_impl },
  { BER_CLASS_CON, 19, BER_FLAGS_IMPLTAG, dissect_redirectionReason_impl },
  { BER_CLASS_CON, 22, BER_FLAGS_IMPLTAG, dissect_systemMyTypeCode_impl },
  { BER_CLASS_CON, 340, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_acgencountered_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_billingID_impl },
  { BER_CLASS_CON, 243, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyName_impl },
  { BER_CLASS_CON, 80, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyNumberDigits1_impl },
  { BER_CLASS_CON, 81, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyNumberDigits2_impl },
  { BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartySubaddress_impl },
  { BER_CLASS_CON, 175, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaServiceOption_impl },
  { BER_CLASS_CON, 163, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_groupInformation_impl },
  { BER_CLASS_CON, 288, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_legInformation_impl },
  { BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mscid_impl },
  { BER_CLASS_CON, 94, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mSCIdentificationNumber_impl },
  { BER_CLASS_CON, 169, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pilotBillingID_impl },
  { BER_CLASS_CON, 168, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pilotNumber_impl },
  { BER_CLASS_CON, 103, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_senderIdentificationNumber_impl },
  { BER_CLASS_CON, 178, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tdmaServiceCode_impl },
  { BER_CLASS_CON, 123, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_transactionCapability_impl },
  { BER_CLASS_CON, 280, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_winCapability_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_TransferToNumberRequest(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              TransferToNumberRequest_set, hf_index, ett_ansi_map_TransferToNumberRequest);

  return offset;
}
static int dissect_transferToNumberRequest(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_TransferToNumberRequest(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_transferToNumberRequest);
}


static const ber_sequence_t TransferToNumberRequestRes_set[] = {
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_digits_Destination_impl },
  { BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_accessDeniedReason_impl },
  { BER_CLASS_CON, 128, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_actionCode_impl },
  { BER_CLASS_CON, 130, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_announcementList_impl },
  { BER_CLASS_CON, 82, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyNumberString1_impl },
  { BER_CLASS_CON, 83, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyNumberString2_impl },
  { BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartySubaddress_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_digits_Carrier_impl },
  { BER_CLASS_CON, 244, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_displayText_impl },
  { BER_CLASS_CON, 299, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_displayText2_impl },
  { BER_CLASS_CON, 140, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_AccountCodeDigits_impl },
  { BER_CLASS_CON, 141, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_AlternateBillingDigits_impl },
  { BER_CLASS_CON, 142, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_BillingDigits_impl },
  { BER_CLASS_CON, 88, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_RedirectionIndicator_impl },
  { BER_CLASS_CON, 305, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_ServiceID_impl },
  { BER_CLASS_CON, 163, BER_FLAGS_OPTIONAL, dissect_groupInformation },
  { BER_CLASS_CON, 93, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mobileDirectoryNumber_impl },
  { BER_CLASS_CON, 96, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_noAnswerTime_impl },
  { BER_CLASS_CON, 147, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_preferredLanguageIndicator_impl },
  { BER_CLASS_CON, 100, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectingNumberDigits_impl },
  { BER_CLASS_CON, 101, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectingNumberString_impl },
  { BER_CLASS_CON, 102, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectingSubaddress_impl },
  { BER_CLASS_CON, 120, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_terminationList_impl },
  { BER_CLASS_CON, 122, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_terminationTriggers_impl },
  { BER_CLASS_CON, 276, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_triggerAddressList_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_TransferToNumberRequestRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              TransferToNumberRequestRes_set, hf_index, ett_ansi_map_TransferToNumberRequestRes);

  return offset;
}
static int dissect_transferToNumberRequestRes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_TransferToNumberRequestRes(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_transferToNumberRequestRes);
}


static const value_string ansi_map_SeizureType_vals[] = {
  {   0, "unspecified" },
  {   1, "loop-back" },
  { 0, NULL }
};


static int
dissect_ansi_map_SeizureType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_seizureType_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_SeizureType(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_seizureType);
}


static const ber_sequence_t TrunkTest_set[] = {
  { BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_interMSCCircuitID_impl },
  { BER_CLASS_CON, 15, BER_FLAGS_IMPLTAG, dissect_seizureType_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_TrunkTest(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              TrunkTest_set, hf_index, ett_ansi_map_TrunkTest);

  return offset;
}
static int dissect_trunkTest(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_TrunkTest(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_trunkTest);
}


static const ber_sequence_t TrunkTestDisconnect_set[] = {
  { BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_interMSCCircuitID_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_TrunkTestDisconnect(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              TrunkTestDisconnect_set, hf_index, ett_ansi_map_TrunkTestDisconnect);

  return offset;
}
static int dissect_trunkTestDisconnect(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_TrunkTestDisconnect(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_trunkTestDisconnect);
}


static const ber_sequence_t Unblocking_set[] = {
  { BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_interMSCCircuitID_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_Unblocking(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              Unblocking_set, hf_index, ett_ansi_map_Unblocking);

  return offset;
}
static int dissect_unblocking(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_Unblocking(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_unblocking);
}


static const ber_sequence_t UnreliableRoamerDataDirective_set[] = {
  { BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mscid_impl },
  { BER_CLASS_CON, 103, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_senderIdentificationNumber_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_UnreliableRoamerDataDirective(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              UnreliableRoamerDataDirective_set, hf_index, ett_ansi_map_UnreliableRoamerDataDirective);

  return offset;
}
static int dissect_unreliableRoamerDataDirective(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_UnreliableRoamerDataDirective(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_unreliableRoamerDataDirective);
}


static const ber_sequence_t UnsolicitedResponse_set[] = {
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_billingID_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_electronicSerialNumber_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_mobileIdentificationNumber_impl },
  { BER_CLASS_CON, 175, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaServiceOption_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_digits_Destination_impl },
  { BER_CLASS_CON, 53, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extendedMSCID_impl },
  { BER_CLASS_CON, 54, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extendedSystemMyTypeCode_impl },
  { BER_CLASS_CON, 32, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pc_ssn_impl },
  { BER_CLASS_CON, 34, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_systemAccessType_impl },
  { BER_CLASS_CON, 178, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tdmaServiceCode_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_UnsolicitedResponse(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              UnsolicitedResponse_set, hf_index, ett_ansi_map_UnsolicitedResponse);

  return offset;
}
static int dissect_unsolicitedResponse(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_UnsolicitedResponse(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_unsolicitedResponse);
}


static const ber_sequence_t UnsolicitedResponseRes_set[] = {
  { BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_accessDeniedReason_impl },
  { BER_CLASS_CON, 75, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_alertCode_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_billingID_impl },
  { BER_CLASS_CON, 243, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyName_impl },
  { BER_CLASS_CON, 80, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyNumberDigits1_impl },
  { BER_CLASS_CON, 81, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyNumberDigits2_impl },
  { BER_CLASS_CON, 82, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyNumberString1_impl },
  { BER_CLASS_CON, 83, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyNumberString2_impl },
  { BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartySubaddress_impl },
  { BER_CLASS_CON, 244, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_displayText_impl },
  { BER_CLASS_CON, 299, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_displayText2_impl },
  { BER_CLASS_CON, 140, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_AccountCodeDigits_impl },
  { BER_CLASS_CON, 141, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_AlternateBillingDigits_impl },
  { BER_CLASS_CON, 142, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_BillingDigits_impl },
  { BER_CLASS_CON, 53, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extendedMSCID_impl },
  { BER_CLASS_CON, 54, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extendedSystemMyTypeCode_impl },
  { BER_CLASS_CON, 288, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_legInformation_impl },
  { BER_CLASS_CON, 93, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mobileDirectoryNumber_impl },
  { BER_CLASS_CON, 94, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mSCIdentificationNumber_impl },
  { BER_CLASS_CON, 97, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_oneTimeFeatureIndicator_impl },
  { BER_CLASS_CON, 32, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pc_ssn_impl },
  { BER_CLASS_CON, 169, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pilotBillingID_impl },
  { BER_CLASS_CON, 168, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pilotNumber_impl },
  { BER_CLASS_CON, 147, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_preferredLanguageIndicator_impl },
  { BER_CLASS_CON, 100, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectingNumberDigits_impl },
  { BER_CLASS_CON, 101, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectingNumberString_impl },
  { BER_CLASS_CON, 245, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectingPartyName_impl },
  { BER_CLASS_CON, 102, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectingSubaddress_impl },
  { BER_CLASS_CON, 121, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_terminationTreatment_impl },
  { BER_CLASS_CON, 122, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_terminationTriggers_impl },
  { BER_CLASS_CON, 276, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_triggerAddressList_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_UnsolicitedResponseRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              UnsolicitedResponseRes_set, hf_index, ett_ansi_map_UnsolicitedResponseRes);

  return offset;
}
static int dissect_unsolicitedResponseRes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_UnsolicitedResponseRes(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_unsolicitedResponseRes);
}



static int
dissect_ansi_map_RequiredParametersMask(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_requiredParametersMask_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_RequiredParametersMask(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_requiredParametersMask);
}


static const ber_sequence_t ParameterRequest_set[] = {
  { BER_CLASS_CON, 236, BER_FLAGS_IMPLTAG, dissect_requiredParametersMask_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_electronicSerialNumber_impl },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_msid },
  { BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mscid_impl },
  { BER_CLASS_CON, 233, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_networkTMSI_impl },
  { BER_CLASS_CON, 32, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pc_ssn_impl },
  { BER_CLASS_CON, 103, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_senderIdentificationNumber_impl },
  { BER_CLASS_CON, 22, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_systemMyTypeCode_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_ParameterRequest(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              ParameterRequest_set, hf_index, ett_ansi_map_ParameterRequest);

  return offset;
}
static int dissect_parameterRequest(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_ParameterRequest(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_parameterRequest);
}


static const value_string ansi_map_ReasonList_vals[] = {
  {   0, "unknown" },
  {   1, "unable-to-configure-ISLP" },
  {   2, "iSLP-failure" },
  {   3, "service-allowed-but-facilities-not-available" },
  {   4, "service-not-allowed" },
  {   5, "no-Response-to-TMSI-assignment" },
  {   6, "required-parameters-unavailable" },
  { 0, NULL }
};


static int
dissect_ansi_map_ReasonList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_reasonList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_ReasonList(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_reasonList);
}


static const ber_sequence_t ParameterRequestRes_set[] = {
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_electronicSerialNumber_impl },
  { BER_CLASS_CON, 242, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_imsi_impl },
  { BER_CLASS_CON, 33, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_locationAreaID_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mobileIdentificationNumber_impl },
  { BER_CLASS_CON, 233, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_networkTMSI_impl },
  { BER_CLASS_CON, 218, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_reasonList_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_ParameterRequestRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              ParameterRequestRes_set, hf_index, ett_ansi_map_ParameterRequestRes);

  return offset;
}
static int dissect_parameterRequestRes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_ParameterRequestRes(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_parameterRequestRes);
}



static int
dissect_ansi_map_NetworkTMSIExpirationTime(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_networkTMSIExpirationTime_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_NetworkTMSIExpirationTime(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_networkTMSIExpirationTime);
}



static int
dissect_ansi_map_NewNetworkTMSI(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ansi_map_DigitsType(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_newNetworkTMSI_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_NewNetworkTMSI(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_newNetworkTMSI);
}


static const ber_sequence_t TMSIDirective_set[] = {
  { BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_electronicSerialNumber_impl },
  { BER_CLASS_CON, 21, BER_FLAGS_IMPLTAG, dissect_mscid_impl },
  { BER_CLASS_CON, 234, BER_FLAGS_IMPLTAG, dissect_networkTMSIExpirationTime_impl },
  { BER_CLASS_CON, 235, BER_FLAGS_IMPLTAG, dissect_newNetworkTMSI_impl },
  { BER_CLASS_CON, 33, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_locationAreaID_impl },
  { BER_CLASS_CON, 233, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_networkTMSI_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_TMSIDirective(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              TMSIDirective_set, hf_index, ett_ansi_map_TMSIDirective);

  return offset;
}
static int dissect_tMSIDirective(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_TMSIDirective(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_tMSIDirective);
}


static const ber_sequence_t TMSIDirectiveRes_set[] = {
  { BER_CLASS_CON, 50, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_denyAccess_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_electronicSerialNumber_impl },
  { BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mscid_impl },
  { BER_CLASS_CON, 218, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_reasonList_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_TMSIDirectiveRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              TMSIDirectiveRes_set, hf_index, ett_ansi_map_TMSIDirectiveRes);

  return offset;
}
static int dissect_tMSIDirectiveRes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_TMSIDirectiveRes(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_tMSIDirectiveRes);
}


static const ber_sequence_t NumberPortabilityRequest_set[] = {
  { BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_digits_impl },
  { BER_CLASS_CON, 340, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_acgencountered_impl },
  { BER_CLASS_CON, 80, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyNumberDigits1_impl },
  { BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mscid_impl },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_msid },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_NumberPortabilityRequest(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              NumberPortabilityRequest_set, hf_index, ett_ansi_map_NumberPortabilityRequest);

  return offset;
}



static int
dissect_ansi_map_ServiceID(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_serviceID_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_ServiceID(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_serviceID);
}



static int
dissect_ansi_map_DataID(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_dataID_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_DataID(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_dataID);
}


static const value_string ansi_map_Change_vals[] = {
  {   1, "setDataItemToDefaultValue" },
  {   2, "addDataItem" },
  {   3, "deleteDataItem" },
  {   4, "replaceDataItemWithAssociatedDataValue" },
  { 0, NULL }
};


static int
dissect_ansi_map_Change(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_change_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_Change(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_change);
}



static int
dissect_ansi_map_DataValue(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_dataValue_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_DataValue(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_dataValue);
}


static const ber_sequence_t DataAccessElement_sequence[] = {
  { BER_CLASS_CON, 251, BER_FLAGS_IMPLTAG, dissect_dataID_impl },
  { BER_CLASS_CON, 248, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_change_impl },
  { BER_CLASS_CON, 256, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dataValue_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_DataAccessElement(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   DataAccessElement_sequence, hf_index, ett_ansi_map_DataAccessElement);

  return offset;
}
static int dissect_dataAccessElement1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_DataAccessElement(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_dataAccessElement1);
}
static int dissect_dataAccessElement2_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_DataAccessElement(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_dataAccessElement2);
}


static const ber_sequence_t DataAccessElementList_item_sequence[] = {
  { BER_CLASS_CON, 249, BER_FLAGS_IMPLTAG, dissect_dataAccessElement1_impl },
  { BER_CLASS_CON, 249, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dataAccessElement2_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_DataAccessElementList_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   DataAccessElementList_item_sequence, hf_index, ett_ansi_map_DataAccessElementList_item);

  return offset;
}
static int dissect_DataAccessElementList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_DataAccessElementList_item(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_DataAccessElementList_item);
}


static const ber_sequence_t DataAccessElementList_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_DataAccessElementList_item },
};

static int
dissect_ansi_map_DataAccessElementList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      DataAccessElementList_sequence_of, hf_index, ett_ansi_map_DataAccessElementList);

  return offset;
}
static int dissect_dataAccessElementList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_DataAccessElementList(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_dataAccessElementList);
}



static int
dissect_ansi_map_TimeDateOffset(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_timeDateOffset_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_TimeDateOffset(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_timeDateOffset);
}



static int
dissect_ansi_map_TimeOfDay(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_timeOfDay_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_TimeOfDay(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_timeOfDay);
}


static const ber_sequence_t ServiceRequest_set[] = {
  { BER_CLASS_CON, 245, BER_FLAGS_IMPLTAG, dissect_serviceID_impl },
  { BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_accessDeniedReason_impl },
  { BER_CLASS_CON, 340, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_acgencountered_impl },
  { BER_CLASS_CON, 90, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_availabilityType_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_billingID_impl },
  { BER_CLASS_CON, 243, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyName_impl },
  { BER_CLASS_CON, 80, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyNumberDigits1_impl },
  { BER_CLASS_CON, 81, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyNumberDigits2_impl },
  { BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartySubaddress_impl },
  { BER_CLASS_CON, 86, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_carrierDigits_impl },
  { BER_CLASS_CON, 162, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_conditionallyDeniedReason_impl },
  { BER_CLASS_CON, 250, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dataAccessElementList_impl },
  { BER_CLASS_CON, 87, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_destinationDigits_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_digits_impl },
  { BER_CLASS_CON, 88, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_RedirectionIndicator_impl },
  { BER_CLASS_CON, 305, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_ServiceID_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_electronicSerialNumber_impl },
  { BER_CLASS_CON, 53, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extendedMSCID_impl },
  { BER_CLASS_CON, 306, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_featureIndicator_impl },
  { BER_CLASS_CON, 163, BER_FLAGS_OPTIONAL, dissect_groupInformation },
  { BER_CLASS_CON, 288, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_legInformation_impl },
  { BER_CLASS_CON, 33, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_locationAreaID_impl },
  { BER_CLASS_CON, 93, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mobileDirectoryNumber_impl },
  { BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mscid_impl },
  { BER_CLASS_CON, 94, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mSCIdentificationNumber_impl },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_msid },
  { BER_CLASS_CON, 32, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pc_ssn_impl },
  { BER_CLASS_CON, 169, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pilotBillingID_impl },
  { BER_CLASS_CON, 168, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pilotNumber_impl },
  { BER_CLASS_CON, 147, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_preferredLanguageIndicator_impl },
  { BER_CLASS_CON, 245, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectingPartyName_impl },
  { BER_CLASS_CON, 100, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectingNumberDigits_impl },
  { BER_CLASS_CON, 102, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectingSubaddress_impl },
  { BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectionReason_impl },
  { BER_CLASS_CON, 150, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_routingDigits_impl },
  { BER_CLASS_CON, 103, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_senderIdentificationNumber_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_servingCellID_impl },
  { BER_CLASS_CON, 22, BER_FLAGS_IMPLTAG, dissect_systemMyTypeCode_impl },
  { BER_CLASS_CON, 119, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_terminationAccessType_impl },
  { BER_CLASS_CON, 275, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_timeDateOffset_impl },
  { BER_CLASS_CON, 309, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_timeOfDay_impl },
  { BER_CLASS_CON, 123, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_transactionCapability_impl },
  { BER_CLASS_CON, 279, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_triggerType_impl },
  { BER_CLASS_CON, 280, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_winCapability_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_ServiceRequest(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              ServiceRequest_set, hf_index, ett_ansi_map_ServiceRequest);

  return offset;
}
static int dissect_serviceRequest(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_ServiceRequest(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_serviceRequest);
}


static const ber_sequence_t ServiceRequestRes_set[] = {
  { BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_accessDeniedReason_impl },
  { BER_CLASS_CON, 128, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_actionCode_impl },
  { BER_CLASS_CON, 75, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_alertCode_impl },
  { BER_CLASS_CON, 130, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_announcementList_impl },
  { BER_CLASS_CON, 243, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyName_impl },
  { BER_CLASS_CON, 82, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyNumberString1_impl },
  { BER_CLASS_CON, 83, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyNumberString2_impl },
  { BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartySubaddress_impl },
  { BER_CLASS_CON, 86, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_carrierDigits_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_digits_impl },
  { BER_CLASS_CON, 244, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_displayText_impl },
  { BER_CLASS_CON, 299, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_displayText2_impl },
  { BER_CLASS_CON, 140, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_AccountCodeDigits_impl },
  { BER_CLASS_CON, 141, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_AlternateBillingDigits_impl },
  { BER_CLASS_CON, 142, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_BillingDigits_impl },
  { BER_CLASS_CON, 311, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_ChargeInformation_impl },
  { BER_CLASS_CON, 88, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_RedirectionIndicator_impl },
  { BER_CLASS_CON, 305, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_ServiceID_impl },
  { BER_CLASS_CON, 163, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_groupInformation_impl },
  { BER_CLASS_CON, 93, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mobileDirectoryNumber_impl },
  { BER_CLASS_CON, 96, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_noAnswerTime_impl },
  { BER_CLASS_CON, 100, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectingNumberDigits_impl },
  { BER_CLASS_CON, 101, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectingNumberString_impl },
  { BER_CLASS_CON, 102, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectingSubaddress_impl },
  { BER_CLASS_CON, 394, BER_FLAGS_IMPLTAG, dissect_resumePIC_impl },
  { BER_CLASS_CON, 150, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_routingDigits_impl },
  { BER_CLASS_CON, 120, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_terminationList_impl },
  { BER_CLASS_CON, 276, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_triggerAddressList_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_ServiceRequestRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              ServiceRequestRes_set, hf_index, ett_ansi_map_ServiceRequestRes);

  return offset;
}
static int dissect_serviceRequestRes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_ServiceRequestRes(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_serviceRequestRes);
}


static const value_string ansi_map_DMH_BillingIndicator_vals[] = {
  {   0, "unspecified" },
  { 0, NULL }
};


static int
dissect_ansi_map_DMH_BillingIndicator(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_dmd_BillingIndicator_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_DMH_BillingIndicator(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_dmd_BillingIndicator);
}


static const ber_sequence_t AnalyzedInformation_set[] = {
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_billingID_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_digits_impl },
  { BER_CLASS_CON, 21, BER_FLAGS_IMPLTAG, dissect_mscid_impl },
  { BER_CLASS_CON, 123, BER_FLAGS_IMPLTAG, dissect_transactionCapability_impl },
  { BER_CLASS_CON, 279, BER_FLAGS_IMPLTAG, dissect_triggerType_impl },
  { BER_CLASS_CON, 280, BER_FLAGS_IMPLTAG, dissect_winCapability_impl },
  { BER_CLASS_CON, 340, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_acgencountered_impl },
  { BER_CLASS_CON, 243, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyName_impl },
  { BER_CLASS_CON, 80, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyNumberDigits1_impl },
  { BER_CLASS_CON, 81, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyNumberDigits2_impl },
  { BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartySubaddress_impl },
  { BER_CLASS_CON, 86, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_carrierDigits_impl },
  { BER_CLASS_CON, 137, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_conferenceCallingIndicator_impl },
  { BER_CLASS_CON, 87, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_destinationDigits_impl },
  { BER_CLASS_CON, 312, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmd_BillingIndicator_impl },
  { BER_CLASS_CON, 311, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_ChargeInformation_impl },
  { BER_CLASS_CON, 88, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_RedirectionIndicator_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_electronicSerialNumber_impl },
  { BER_CLASS_CON, 306, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_featureIndicator_impl },
  { BER_CLASS_CON, 33, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_locationAreaID_impl },
  { BER_CLASS_CON, 93, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mobileDirectoryNumber_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mobileIdentificationNumber_impl },
  { BER_CLASS_CON, 94, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mSCIdentificationNumber_impl },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_msid },
  { BER_CLASS_CON, 97, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_oneTimeFeatureIndicator_impl },
  { BER_CLASS_CON, 147, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_preferredLanguageIndicator_impl },
  { BER_CLASS_CON, 100, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectingNumberDigits_impl },
  { BER_CLASS_CON, 245, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectingPartyName_impl },
  { BER_CLASS_CON, 102, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectingSubaddress_impl },
  { BER_CLASS_CON, 150, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_routingDigits_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_servingCellID_impl },
  { BER_CLASS_CON, 22, BER_FLAGS_IMPLTAG, dissect_systemMyTypeCode_impl },
  { BER_CLASS_CON, 119, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_terminationAccessType_impl },
  { BER_CLASS_CON, 275, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_timeDateOffset_impl },
  { BER_CLASS_CON, 309, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_timeOfDay_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_AnalyzedInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              AnalyzedInformation_set, hf_index, ett_ansi_map_AnalyzedInformation);

  return offset;
}
static int dissect_analyzedInformation(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_AnalyzedInformation(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_analyzedInformation);
}


static const ber_sequence_t AnalyzedInformationRes_set[] = {
  { BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_accessDeniedReason_impl },
  { BER_CLASS_CON, 128, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_actionCode_impl },
  { BER_CLASS_CON, 130, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_announcementList_impl },
  { BER_CLASS_CON, 86, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_carrierDigits_impl },
  { BER_CLASS_CON, 137, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_conferenceCallingIndicator_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_digits_impl },
  { BER_CLASS_CON, 244, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_displayText_impl },
  { BER_CLASS_CON, 140, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_AccountCodeDigits_impl },
  { BER_CLASS_CON, 141, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_AlternateBillingDigits_impl },
  { BER_CLASS_CON, 142, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_BillingDigits_impl },
  { BER_CLASS_CON, 88, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_RedirectionIndicator_impl },
  { BER_CLASS_CON, 305, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_ServiceID_impl },
  { BER_CLASS_CON, 96, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_noAnswerTime_impl },
  { BER_CLASS_CON, 97, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_oneTimeFeatureIndicator_impl },
  { BER_CLASS_CON, 100, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectingNumberDigits_impl },
  { BER_CLASS_CON, 394, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_resumePIC_impl },
  { BER_CLASS_CON, 150, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_routingDigits_impl },
  { BER_CLASS_CON, 120, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_terminationList_impl },
  { BER_CLASS_CON, 122, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_terminationTriggers_impl },
  { BER_CLASS_CON, 276, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_triggerAddressList_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_AnalyzedInformationRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              AnalyzedInformationRes_set, hf_index, ett_ansi_map_AnalyzedInformationRes);

  return offset;
}
static int dissect_analyzedInformationRes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_AnalyzedInformationRes(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_analyzedInformationRes);
}


static const value_string ansi_map_FailureType_vals[] = {
  {   1, "callAbandoned" },
  {   2, "resourceDisconnect" },
  {   3, "failureAtMSC" },
  {   4, "sSFTExpiration" },
  { 0, NULL }
};


static int
dissect_ansi_map_FailureType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_failureType_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_FailureType(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_failureType);
}



static int
dissect_ansi_map_FailureCause(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_failureCause_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_FailureCause(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_failureCause);
}


static const ber_sequence_t ConnectionFailureReport_set[] = {
  { BER_CLASS_CON, 260, BER_FLAGS_IMPLTAG, dissect_failureType_impl },
  { BER_CLASS_CON, 387, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_failureCause_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_ConnectionFailureReport(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              ConnectionFailureReport_set, hf_index, ett_ansi_map_ConnectionFailureReport);

  return offset;
}
static int dissect_connectionFailureReport(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_ConnectionFailureReport(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_connectionFailureReport);
}


static const ber_sequence_t ConnectResource_set[] = {
  { BER_CLASS_CON, 87, BER_FLAGS_IMPLTAG, dissect_destinationDigits_impl },
  { BER_CLASS_CON, 86, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_carrierDigits_impl },
  { BER_CLASS_CON, 150, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_outingDigits_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_ConnectResource(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              ConnectResource_set, hf_index, ett_ansi_map_ConnectResource);

  return offset;
}
static int dissect_connectResource(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_ConnectResource(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_connectResource);
}


static const ber_sequence_t FacilitySelectedAndAvailable_set[] = {
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_billingID_impl },
  { BER_CLASS_CON, 21, BER_FLAGS_IMPLTAG, dissect_mscid_impl },
  { BER_CLASS_CON, 123, BER_FLAGS_IMPLTAG, dissect_transactionCapability_impl },
  { BER_CLASS_CON, 279, BER_FLAGS_IMPLTAG, dissect_triggerType_impl },
  { BER_CLASS_CON, 280, BER_FLAGS_IMPLTAG, dissect_winCapability_impl },
  { BER_CLASS_CON, 340, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_acgencountered_impl },
  { BER_CLASS_CON, 243, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyName_impl },
  { BER_CLASS_CON, 80, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyNumberDigits1_impl },
  { BER_CLASS_CON, 81, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyNumberDigits2_impl },
  { BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartySubaddress_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_electronicSerialNumber_impl },
  { BER_CLASS_CON, 163, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_groupInformation_impl },
  { BER_CLASS_CON, 288, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_legInformation_impl },
  { BER_CLASS_CON, 33, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_locationAreaID_impl },
  { BER_CLASS_CON, 93, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mobileDirectoryNumber_impl },
  { BER_CLASS_CON, 94, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mSCIdentificationNumber_impl },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_msid },
  { BER_CLASS_CON, 97, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_oneTimeFeatureIndicator_impl },
  { BER_CLASS_CON, 169, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pilotBillingID_impl },
  { BER_CLASS_CON, 168, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pilotNumber_impl },
  { BER_CLASS_CON, 147, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_preferredLanguageIndicator_impl },
  { BER_CLASS_CON, 100, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectingNumberDigits_impl },
  { BER_CLASS_CON, 245, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectingPartyName_impl },
  { BER_CLASS_CON, 102, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectingSubaddress_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_servingCellID_impl },
  { BER_CLASS_CON, 22, BER_FLAGS_IMPLTAG, dissect_systemMyTypeCode_impl },
  { BER_CLASS_CON, 119, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_terminationAccessType_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_FacilitySelectedAndAvailable(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              FacilitySelectedAndAvailable_set, hf_index, ett_ansi_map_FacilitySelectedAndAvailable);

  return offset;
}
static int dissect_facilitySelectedAndAvailable(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_FacilitySelectedAndAvailable(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_facilitySelectedAndAvailable);
}


static const ber_sequence_t FacilitySelectedAndAvailableRes_set[] = {
  { BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_accessDeniedReason_impl },
  { BER_CLASS_CON, 128, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_actionCode_impl },
  { BER_CLASS_CON, 75, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_alertCode_impl },
  { BER_CLASS_CON, 244, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_displayText_impl },
  { BER_CLASS_CON, 140, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_AccountCodeDigits_impl },
  { BER_CLASS_CON, 141, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_AlternateBillingDigits_impl },
  { BER_CLASS_CON, 142, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_BillingDigits_impl },
  { BER_CLASS_CON, 311, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_ChargeInformation_impl },
  { BER_CLASS_CON, 88, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_RedirectionIndicator_impl },
  { BER_CLASS_CON, 305, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_ServiceID_impl },
  { BER_CLASS_CON, 96, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_noAnswerTime_impl },
  { BER_CLASS_CON, 97, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_oneTimeFeatureIndicator_impl },
  { BER_CLASS_CON, 394, BER_FLAGS_IMPLTAG, dissect_resumePIC_impl },
  { BER_CLASS_CON, 122, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_terminationTriggers_impl },
  { BER_CLASS_CON, 276, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_triggerAddressList_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_FacilitySelectedAndAvailableRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              FacilitySelectedAndAvailableRes_set, hf_index, ett_ansi_map_FacilitySelectedAndAvailableRes);

  return offset;
}
static int dissect_facilitySelectedAndAvailableRes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_FacilitySelectedAndAvailableRes(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_facilitySelectedAndAvailableRes);
}



static int
dissect_ansi_map_DatabaseKey(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_databaseKey_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_DatabaseKey(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_databaseKey);
}


static const ber_sequence_t ServiceDataAccessElement_sequence[] = {
  { BER_CLASS_CON, 250, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dataAccessElementList_impl },
  { BER_CLASS_CON, 246, BER_FLAGS_IMPLTAG, dissect_serviceID_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_ServiceDataAccessElement(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ServiceDataAccessElement_sequence, hf_index, ett_ansi_map_ServiceDataAccessElement);

  return offset;
}
static int dissect_ServiceDataAccessElementList_item_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_ServiceDataAccessElement(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_ServiceDataAccessElementList_item);
}


static const ber_sequence_t ServiceDataAccessElementList_sequence_of[1] = {
  { BER_CLASS_CON, 398, BER_FLAGS_IMPLTAG, dissect_ServiceDataAccessElementList_item_impl },
};

static int
dissect_ansi_map_ServiceDataAccessElementList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      ServiceDataAccessElementList_sequence_of, hf_index, ett_ansi_map_ServiceDataAccessElementList);

  return offset;
}
static int dissect_serviceDataAccessElementList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_ServiceDataAccessElementList(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_serviceDataAccessElementList);
}


static const value_string ansi_map_AllOrNone_vals[] = {
  {   0, "notUsed" },
  {   1, "allChangesMustSucceedOrNoneShouldBeApplied" },
  {   2, "treatEachChangeIndependently" },
  { 0, NULL }
};


static int
dissect_ansi_map_AllOrNone(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_allOrNone_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_AllOrNone(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_allOrNone);
}


static const ber_sequence_t ModificationRequest_sequence[] = {
  { BER_CLASS_CON, 399, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_serviceDataAccessElementList_impl },
  { BER_CLASS_CON, 247, BER_FLAGS_IMPLTAG, dissect_allOrNone_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_ModificationRequest(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ModificationRequest_sequence, hf_index, ett_ansi_map_ModificationRequest);

  return offset;
}
static int dissect_ModificationRequestList_item_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_ModificationRequest(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_ModificationRequestList_item);
}


static const ber_sequence_t ModificationRequestList_sequence_of[1] = {
  { BER_CLASS_CON, 390, BER_FLAGS_IMPLTAG, dissect_ModificationRequestList_item_impl },
};

static int
dissect_ansi_map_ModificationRequestList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      ModificationRequestList_sequence_of, hf_index, ett_ansi_map_ModificationRequestList);

  return offset;
}
static int dissect_modificationRequestList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_ModificationRequestList(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_modificationRequestList);
}


static const ber_sequence_t Modify_set[] = {
  { BER_CLASS_CON, 252, BER_FLAGS_IMPLTAG, dissect_databaseKey_impl },
  { BER_CLASS_CON, 391, BER_FLAGS_IMPLTAG, dissect_modificationRequestList_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_Modify(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              Modify_set, hf_index, ett_ansi_map_Modify);

  return offset;
}
static int dissect_modify(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_Modify(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_modify);
}


static const value_string ansi_map_DataResult_vals[] = {
  {   0, "not-used" },
  {   1, "successful" },
  {   2, "unsuccessful-unspecified" },
  {   3, "unsuccessful-no-default-value-available" },
  {   4, "reserved" },
  { 0, NULL }
};


static int
dissect_ansi_map_DataResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_dataResult_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_DataResult(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_dataResult);
}


static const ber_sequence_t DataUpdateResult_sequence[] = {
  { BER_CLASS_CON, 251, BER_FLAGS_IMPLTAG, dissect_dataID_impl },
  { BER_CLASS_CON, 253, BER_FLAGS_IMPLTAG, dissect_dataResult_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_DataUpdateResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   DataUpdateResult_sequence, hf_index, ett_ansi_map_DataUpdateResult);

  return offset;
}
static int dissect_DataUpdateResultList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_DataUpdateResult(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_DataUpdateResultList_item);
}


static const ber_sequence_t DataUpdateResultList_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_DataUpdateResultList_item },
};

static int
dissect_ansi_map_DataUpdateResultList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      DataUpdateResultList_sequence_of, hf_index, ett_ansi_map_DataUpdateResultList);

  return offset;
}
static int dissect_dataUpdateResultList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_DataUpdateResultList(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_dataUpdateResultList);
}


static const ber_sequence_t ServiceDataResult_sequence[] = {
  { BER_CLASS_CON, 255, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dataUpdateResultList_impl },
  { BER_CLASS_CON, 246, BER_FLAGS_IMPLTAG, dissect_serviceID_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_ServiceDataResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ServiceDataResult_sequence, hf_index, ett_ansi_map_ServiceDataResult);

  return offset;
}
static int dissect_ServiceDataResultList_item_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_ServiceDataResult(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_ServiceDataResultList_item);
}


static const ber_sequence_t ServiceDataResultList_sequence_of[1] = {
  { BER_CLASS_CON, 272, BER_FLAGS_IMPLTAG, dissect_ServiceDataResultList_item_impl },
};

static int
dissect_ansi_map_ServiceDataResultList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      ServiceDataResultList_sequence_of, hf_index, ett_ansi_map_ServiceDataResultList);

  return offset;
}
static int dissect_serviceDataResultList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_ServiceDataResultList(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_serviceDataResultList);
}


static const value_string ansi_map_ModificationResult_vals[] = {
  { 253, "dataResult" },
  { 273, "serviceDataResultList" },
  { 0, NULL }
};

static const ber_choice_t ModificationResult_choice[] = {
  { 253, BER_CLASS_CON, 253, BER_FLAGS_IMPLTAG, dissect_dataResult_impl },
  { 273, BER_CLASS_CON, 273, BER_FLAGS_IMPLTAG, dissect_serviceDataResultList_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_ansi_map_ModificationResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 ModificationResult_choice, hf_index, ett_ansi_map_ModificationResult,
                                 NULL);

  return offset;
}
static int dissect_ModificationResultList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_ModificationResult(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_ModificationResultList_item);
}


static const ber_sequence_t ModificationResultList_sequence_of[1] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ModificationResultList_item },
};

static int
dissect_ansi_map_ModificationResultList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      ModificationResultList_sequence_of, hf_index, ett_ansi_map_ModificationResultList);

  return offset;
}
static int dissect_modificationResultList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_ModificationResultList(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_modificationResultList);
}


static const ber_sequence_t ModifyRes_set[] = {
  { BER_CLASS_CON, 392, BER_FLAGS_IMPLTAG, dissect_modificationResultList_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_ModifyRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              ModifyRes_set, hf_index, ett_ansi_map_ModifyRes);

  return offset;
}
static int dissect_modifyRes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_ModifyRes(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_modifyRes);
}


static const ber_sequence_t Search_set[] = {
  { BER_CLASS_CON, 252, BER_FLAGS_IMPLTAG, dissect_databaseKey_impl },
  { BER_CLASS_CON, 399, BER_FLAGS_IMPLTAG, dissect_serviceDataAccessElementList_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_Search(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              Search_set, hf_index, ett_ansi_map_Search);

  return offset;
}
static int dissect_search(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_Search(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_search);
}


static const ber_sequence_t SearchRes_set[] = {
  { BER_CLASS_CON, 399, BER_FLAGS_IMPLTAG, dissect_serviceDataAccessElementList_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_SearchRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              SearchRes_set, hf_index, ett_ansi_map_SearchRes);

  return offset;
}
static int dissect_searchRes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_SearchRes(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_searchRes);
}



static int
dissect_ansi_map_PrivateSpecializedResource(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_privateSpecializedResource_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_PrivateSpecializedResource(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_privateSpecializedResource);
}



static int
dissect_ansi_map_SpecializedResource(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_specializedResource_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_SpecializedResource(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_specializedResource);
}


static const ber_sequence_t SeizeResource_set[] = {
  { BER_CLASS_CON, 147, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_preferredLanguageIndicator_impl },
  { BER_CLASS_CON, 383, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_privateSpecializedResource_impl },
  { BER_CLASS_CON, 274, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_specializedResource_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_SeizeResource(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              SeizeResource_set, hf_index, ett_ansi_map_SeizeResource);

  return offset;
}
static int dissect_seizeResource(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_SeizeResource(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_seizeResource);
}


static const ber_sequence_t SeizeResourceRes_set[] = {
  { BER_CLASS_CON, 87, BER_FLAGS_IMPLTAG, dissect_destinationDigits_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_SeizeResourceRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              SeizeResourceRes_set, hf_index, ett_ansi_map_SeizeResourceRes);

  return offset;
}
static int dissect_seizeResourceRes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_SeizeResourceRes(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_seizeResourceRes);
}



static int
dissect_ansi_map_ScriptName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_scriptName_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_ScriptName(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_scriptName);
}



static int
dissect_ansi_map_ScriptArgument(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_scriptArgument_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_ScriptArgument(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_scriptArgument);
}


static const ber_sequence_t ExecuteScript_sequence[] = {
  { BER_CLASS_CON, 396, BER_FLAGS_IMPLTAG, dissect_scriptName_impl },
  { BER_CLASS_CON, 395, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_scriptArgument_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_ExecuteScript(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ExecuteScript_sequence, hf_index, ett_ansi_map_ExecuteScript);

  return offset;
}
static int dissect_executeScript_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_ExecuteScript(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_executeScript);
}


static const ber_sequence_t SRFDirective_set[] = {
  { BER_CLASS_CON, 130, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_announcementList_impl },
  { BER_CLASS_CON, 139, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_digitCollectionControl_impl },
  { BER_CLASS_CON, 386, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_executeScript_impl },
  { BER_CLASS_CON, 93, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mobileDirectoryNumber_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_SRFDirective(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              SRFDirective_set, hf_index, ett_ansi_map_SRFDirective);

  return offset;
}
static int dissect_sRFDirective(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_SRFDirective(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_sRFDirective);
}



static int
dissect_ansi_map_ScriptResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_scriptResult_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_ScriptResult(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_scriptResult);
}


static const ber_sequence_t SRFDirectiveRes_set[] = {
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_digits_impl },
  { BER_CLASS_CON, 397, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_scriptResult_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_SRFDirectiveRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              SRFDirectiveRes_set, hf_index, ett_ansi_map_SRFDirectiveRes);

  return offset;
}
static int dissect_sRFDirectiveRes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_SRFDirectiveRes(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_sRFDirectiveRes);
}


static const ber_sequence_t TBusy_set[] = {
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_billingID_impl },
  { BER_CLASS_CON, 21, BER_FLAGS_IMPLTAG, dissect_mscid_impl },
  { BER_CLASS_CON, 123, BER_FLAGS_IMPLTAG, dissect_transactionCapability_impl },
  { BER_CLASS_CON, 279, BER_FLAGS_IMPLTAG, dissect_triggerType_impl },
  { BER_CLASS_CON, 280, BER_FLAGS_IMPLTAG, dissect_winCapability_impl },
  { BER_CLASS_CON, 340, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_acgencountered_impl },
  { BER_CLASS_CON, 80, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyNumberDigits1_impl },
  { BER_CLASS_CON, 81, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyNumberDigits2_impl },
  { BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartySubaddress_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_electronicSerialNumber_impl },
  { BER_CLASS_CON, 163, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_groupInformation_impl },
  { BER_CLASS_CON, 288, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_legInformation_impl },
  { BER_CLASS_CON, 33, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_locationAreaID_impl },
  { BER_CLASS_CON, 93, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mobileDirectoryNumber_impl },
  { BER_CLASS_CON, 94, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mSCIdentificationNumber_impl },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_msid },
  { BER_CLASS_CON, 97, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_oneTimeFeatureIndicator_impl },
  { BER_CLASS_CON, 169, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pilotBillingID_impl },
  { BER_CLASS_CON, 168, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pilotNumber_impl },
  { BER_CLASS_CON, 147, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_preferredLanguageIndicator_impl },
  { BER_CLASS_CON, 100, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectingNumberDigits_impl },
  { BER_CLASS_CON, 102, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectingSubaddress_impl },
  { BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectionReason_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_servingCellID_impl },
  { BER_CLASS_CON, 22, BER_FLAGS_IMPLTAG, dissect_systemMyTypeCode_impl },
  { BER_CLASS_CON, 119, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_terminationAccessType_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_TBusy(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              TBusy_set, hf_index, ett_ansi_map_TBusy);

  return offset;
}
static int dissect_tBusy(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_TBusy(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_tBusy);
}


static const ber_sequence_t TBusyRes_set[] = {
  { BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_accessDeniedReason_impl },
  { BER_CLASS_CON, 128, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_actionCode_impl },
  { BER_CLASS_CON, 130, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_announcementList_impl },
  { BER_CLASS_CON, 82, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyNumberString1_impl },
  { BER_CLASS_CON, 83, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyNumberString2_impl },
  { BER_CLASS_CON, 86, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_carrierDigits_impl },
  { BER_CLASS_CON, 244, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_displayText_impl },
  { BER_CLASS_CON, 141, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_AlternateBillingDigits_impl },
  { BER_CLASS_CON, 142, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_BillingDigits_impl },
  { BER_CLASS_CON, 88, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_RedirectionIndicator_impl },
  { BER_CLASS_CON, 305, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_ServiceID_impl },
  { BER_CLASS_CON, 163, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_groupInformation_impl },
  { BER_CLASS_CON, 97, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_oneTimeFeatureIndicator_impl },
  { BER_CLASS_CON, 168, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pilotNumber_impl },
  { BER_CLASS_CON, 147, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_preferredLanguageIndicator_impl },
  { BER_CLASS_CON, 100, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectingNumberDigits_impl },
  { BER_CLASS_CON, 394, BER_FLAGS_IMPLTAG, dissect_resumePIC_impl },
  { BER_CLASS_CON, 150, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_routingDigits_impl },
  { BER_CLASS_CON, 120, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_terminationList_impl },
  { BER_CLASS_CON, 122, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_terminationTriggers_impl },
  { BER_CLASS_CON, 276, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_triggerAddressList_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_TBusyRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              TBusyRes_set, hf_index, ett_ansi_map_TBusyRes);

  return offset;
}
static int dissect_tBusyRes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_TBusyRes(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_tBusyRes);
}


static const ber_sequence_t TNoAnswer_set[] = {
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_billingID_impl },
  { BER_CLASS_CON, 21, BER_FLAGS_IMPLTAG, dissect_mscid_impl },
  { BER_CLASS_CON, 123, BER_FLAGS_IMPLTAG, dissect_transactionCapability_impl },
  { BER_CLASS_CON, 279, BER_FLAGS_IMPLTAG, dissect_triggerType_impl },
  { BER_CLASS_CON, 280, BER_FLAGS_IMPLTAG, dissect_winCapability_impl },
  { BER_CLASS_CON, 340, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_acgencountered_impl },
  { BER_CLASS_CON, 80, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyNumberDigits1_impl },
  { BER_CLASS_CON, 81, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyNumberDigits2_impl },
  { BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartySubaddress_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_electronicSerialNumber_impl },
  { BER_CLASS_CON, 163, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_groupInformation_impl },
  { BER_CLASS_CON, 288, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_legInformation_impl },
  { BER_CLASS_CON, 33, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_locationAreaID_impl },
  { BER_CLASS_CON, 93, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mobileDirectoryNumber_impl },
  { BER_CLASS_CON, 94, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mSCIdentificationNumber_impl },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_msid },
  { BER_CLASS_CON, 97, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_oneTimeFeatureIndicator_impl },
  { BER_CLASS_CON, 169, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pilotBillingID_impl },
  { BER_CLASS_CON, 168, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pilotNumber_impl },
  { BER_CLASS_CON, 147, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_preferredLanguageIndicator_impl },
  { BER_CLASS_CON, 100, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectingNumberDigits_impl },
  { BER_CLASS_CON, 102, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectingSubaddress_impl },
  { BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectionReason_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_servingCellID_impl },
  { BER_CLASS_CON, 22, BER_FLAGS_IMPLTAG, dissect_systemMyTypeCode_impl },
  { BER_CLASS_CON, 119, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_terminationAccessType_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_TNoAnswer(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              TNoAnswer_set, hf_index, ett_ansi_map_TNoAnswer);

  return offset;
}
static int dissect_tNoAnswer(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_TNoAnswer(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_tNoAnswer);
}


static const ber_sequence_t TNoAnswerRes_set[] = {
  { BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_accessDeniedReason_impl },
  { BER_CLASS_CON, 128, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_actionCode_impl },
  { BER_CLASS_CON, 130, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_announcementList_impl },
  { BER_CLASS_CON, 82, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyNumberString1_impl },
  { BER_CLASS_CON, 83, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyNumberString2_impl },
  { BER_CLASS_CON, 86, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_carrierDigits_impl },
  { BER_CLASS_CON, 244, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_displayText_impl },
  { BER_CLASS_CON, 140, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_AccountCodeDigits_impl },
  { BER_CLASS_CON, 141, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_AlternateBillingDigits_impl },
  { BER_CLASS_CON, 142, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_BillingDigits_impl },
  { BER_CLASS_CON, 88, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_RedirectionIndicator_impl },
  { BER_CLASS_CON, 305, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_ServiceID_impl },
  { BER_CLASS_CON, 163, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_groupInformation_impl },
  { BER_CLASS_CON, 97, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_oneTimeFeatureIndicator_impl },
  { BER_CLASS_CON, 168, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pilotNumber_impl },
  { BER_CLASS_CON, 147, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_preferredLanguageIndicator_impl },
  { BER_CLASS_CON, 100, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectingNumberDigits_impl },
  { BER_CLASS_CON, 394, BER_FLAGS_IMPLTAG, dissect_resumePIC_impl },
  { BER_CLASS_CON, 150, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_routingDigits_impl },
  { BER_CLASS_CON, 120, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_terminationList_impl },
  { BER_CLASS_CON, 122, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_terminationTriggers_impl },
  { BER_CLASS_CON, 276, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_triggerAddressList_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_TNoAnswerRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              TNoAnswerRes_set, hf_index, ett_ansi_map_TNoAnswerRes);

  return offset;
}
static int dissect_tNoAnswerRes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_TNoAnswerRes(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_tNoAnswerRes);
}


static const ber_sequence_t ChangeFacilities_set[] = {
  { BER_CLASS_CON, 67, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaPrivateLongCodeMask_impl },
  { BER_CLASS_CON, 174, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaServiceConfigurationRecord_impl },
  { BER_CLASS_CON, 215, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dataKey_impl },
  { BER_CLASS_CON, 216, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dataPrivacyParameters_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_electronicSerialNumber_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_interMSCCircuitID_impl },
  { BER_CLASS_CON, 217, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ilspInformation_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mobileIdentificationNumber_impl },
  { BER_CLASS_CON, 40, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_randomVariable_impl },
  { BER_CLASS_CON, 220, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tdmaBandwidth_impl },
  { BER_CLASS_CON, 178, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tdmaServiceCode_impl },
  { BER_CLASS_CON, 48, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_voicePrivacyMask_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_ChangeFacilities(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              ChangeFacilities_set, hf_index, ett_ansi_map_ChangeFacilities);

  return offset;
}
static int dissect_changeFacilities(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_ChangeFacilities(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_changeFacilities);
}


static const ber_sequence_t ChangeFacilitiesRes_set[] = {
  { BER_CLASS_CON, 218, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_reasonList_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_ChangeFacilitiesRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              ChangeFacilitiesRes_set, hf_index, ett_ansi_map_ChangeFacilitiesRes);

  return offset;
}
static int dissect_changeFacilitiesRes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_ChangeFacilitiesRes(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_changeFacilitiesRes);
}



static int
dissect_ansi_map_TDMAVoiceMode(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_tdmaVoiceMode_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_TDMAVoiceMode(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_tdmaVoiceMode);
}


static const ber_sequence_t ChangeService_set[] = {
  { BER_CLASS_CON, 174, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaServiceConfigurationRecord_impl },
  { BER_CLASS_CON, 176, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaServiceOptionList_impl },
  { BER_CLASS_CON, 214, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_changeServiceAttributes_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_electronicSerialNumber_impl },
  { BER_CLASS_CON, 217, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ilspInformation_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mobileIdentificationNumber_impl },
  { BER_CLASS_CON, 220, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tdmaBandwidth_impl },
  { BER_CLASS_CON, 222, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tdmaDataMode_impl },
  { BER_CLASS_CON, 178, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tdmaServiceCode_impl },
  { BER_CLASS_CON, 223, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tdmaVoiceMode_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_ChangeService(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              ChangeService_set, hf_index, ett_ansi_map_ChangeService);

  return offset;
}
static int dissect_changeService(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_ChangeService(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_changeService);
}


static const ber_sequence_t ChangeServiceRes_set[] = {
  { BER_CLASS_CON, 67, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaPrivateLongCodeMask_impl },
  { BER_CLASS_CON, 174, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaServiceConfigurationRecord_impl },
  { BER_CLASS_CON, 176, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaServiceOptionList_impl },
  { BER_CLASS_CON, 214, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_changeServiceAttributes_impl },
  { BER_CLASS_CON, 215, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dataKey_impl },
  { BER_CLASS_CON, 216, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dataPrivacyParameters_impl },
  { BER_CLASS_CON, 40, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_randomVariable_impl },
  { BER_CLASS_CON, 218, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_reasonList_impl },
  { BER_CLASS_CON, 178, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tdmaServiceCode_impl },
  { BER_CLASS_CON, 48, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_voicePrivacyMask_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_ChangeServiceRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              ChangeServiceRes_set, hf_index, ett_ansi_map_ChangeServiceRes);

  return offset;
}
static int dissect_changeServiceRes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_ChangeServiceRes(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_changeServiceRes);
}


static const ber_sequence_t MessageDirective_set[] = {
  { BER_CLASS_CON, 92, BER_FLAGS_IMPLTAG, dissect_messageWaitingNotificationCount_impl },
  { BER_CLASS_CON, 93, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mobileDirectoryNumber_impl },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_msid },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_MessageDirective(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              MessageDirective_set, hf_index, ett_ansi_map_MessageDirective);

  return offset;
}
static int dissect_messageDirective(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_MessageDirective(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_messageDirective);
}


static const ber_sequence_t BulkDisconnection_set[] = {
  { BER_CLASS_CON, 21, BER_FLAGS_IMPLTAG, dissect_mscid_impl },
  { BER_CLASS_CON, 275, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_timeDateOffset_impl },
  { BER_CLASS_CON, 309, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_timeOfDay_impl },
  { BER_CLASS_CON, 94, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mSCIdentificationNumber_impl },
  { BER_CLASS_CON, 103, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_senderIdentificationNumber_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_BulkDisconnection(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              BulkDisconnection_set, hf_index, ett_ansi_map_BulkDisconnection);

  return offset;
}
static int dissect_bulkDisconnection(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_BulkDisconnection(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_bulkDisconnection);
}


static const ber_sequence_t CallControlDirective_set[] = {
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_billingID_impl },
  { BER_CLASS_CON, 21, BER_FLAGS_IMPLTAG, dissect_mscid_impl },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_msid },
  { BER_CLASS_CON, 128, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_actionCode_impl },
  { BER_CLASS_CON, 130, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_announcementList_impl },
  { BER_CLASS_CON, 244, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_displayText_impl },
  { BER_CLASS_CON, 140, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_AccountCodeDigits_impl },
  { BER_CLASS_CON, 141, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_AlternateBillingDigits_impl },
  { BER_CLASS_CON, 142, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_BillingDigits_impl },
  { BER_CLASS_CON, 311, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_ChargeInformation_impl },
  { BER_CLASS_CON, 88, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_RedirectionIndicator_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_electronicSerialNumber_impl },
  { BER_CLASS_CON, 93, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mobileDirectoryNumber_impl },
  { BER_CLASS_CON, 147, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_preferredLanguageIndicator_impl },
  { BER_CLASS_CON, 120, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_terminationList_impl },
  { BER_CLASS_CON, 276, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_triggerAddressList_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_CallControlDirective(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              CallControlDirective_set, hf_index, ett_ansi_map_CallControlDirective);

  return offset;
}
static int dissect_callControlDirective(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_CallControlDirective(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_callControlDirective);
}


static const value_string ansi_map_CallStatus_vals[] = {
  {   0, "not-used" },
  {   1, "call-Setup-in-Progress" },
  {   2, "called-Party" },
  {   3, "locally-Allowed-Call-No-Action" },
  { 0, NULL }
};


static int
dissect_ansi_map_CallStatus(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_callStatus_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_CallStatus(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_callStatus);
}


static const ber_sequence_t CallControlDirectiveRes_set[] = {
  { BER_CLASS_CON, 310, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callStatus_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_CallControlDirectiveRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              CallControlDirectiveRes_set, hf_index, ett_ansi_map_CallControlDirectiveRes);

  return offset;
}
static int dissect_callControlDirectiveRes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_CallControlDirectiveRes(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_callControlDirectiveRes);
}


static const ber_sequence_t OAnswer_set[] = {
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_billingID_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_electronicSerialNumber_impl },
  { BER_CLASS_CON, 21, BER_FLAGS_IMPLTAG, dissect_mscid_impl },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_msid },
  { BER_CLASS_CON, 275, BER_FLAGS_IMPLTAG, dissect_timeDateOffset_impl },
  { BER_CLASS_CON, 309, BER_FLAGS_IMPLTAG, dissect_timeOfDay_impl },
  { BER_CLASS_CON, 279, BER_FLAGS_IMPLTAG, dissect_triggerType_impl },
  { BER_CLASS_CON, 33, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_locationAreaID_impl },
  { BER_CLASS_CON, 93, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mobileDirectoryNumber_impl },
  { BER_CLASS_CON, 306, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_featureIndicator_impl },
  { BER_CLASS_CON, 94, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mSCIdentificationNumber_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_servingCellID_impl },
  { BER_CLASS_CON, 22, BER_FLAGS_IMPLTAG, dissect_systemMyTypeCode_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_OAnswer(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              OAnswer_set, hf_index, ett_ansi_map_OAnswer);

  return offset;
}
static int dissect_oAnswer(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_OAnswer(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_oAnswer);
}


static const value_string ansi_map_ReleaseCause_vals[] = {
  {   0, "unspecified" },
  {   1, "calling-Party" },
  {   2, "called-Party" },
  {   3, "commanded-Disconnect" },
  { 0, NULL }
};


static int
dissect_ansi_map_ReleaseCause(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_releaseCause_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_ReleaseCause(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_releaseCause);
}


static const ber_sequence_t ODisconnect_set[] = {
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_billingID_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_electronicSerialNumber_impl },
  { BER_CLASS_CON, 21, BER_FLAGS_IMPLTAG, dissect_mscid_impl },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_msid },
  { BER_CLASS_CON, 308, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_releaseCause_impl },
  { BER_CLASS_CON, 275, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_timeDateOffset_impl },
  { BER_CLASS_CON, 309, BER_FLAGS_IMPLTAG, dissect_timeOfDay_impl },
  { BER_CLASS_CON, 123, BER_FLAGS_IMPLTAG, dissect_transactionCapability_impl },
  { BER_CLASS_CON, 280, BER_FLAGS_IMPLTAG, dissect_winCapability_impl },
  { BER_CLASS_CON, 279, BER_FLAGS_IMPLTAG, dissect_triggerType_impl },
  { BER_CLASS_CON, 33, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_locationAreaID_impl },
  { BER_CLASS_CON, 93, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mobileDirectoryNumber_impl },
  { BER_CLASS_CON, 94, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mSCIdentificationNumber_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_servingCellID_impl },
  { BER_CLASS_CON, 22, BER_FLAGS_IMPLTAG, dissect_systemMyTypeCode_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_ODisconnect(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              ODisconnect_set, hf_index, ett_ansi_map_ODisconnect);

  return offset;
}
static int dissect_oDisconnect(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_ODisconnect(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_oDisconnect);
}


static const ber_sequence_t ODisconnectRes_set[] = {
  { BER_CLASS_CON, 130, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_announcementList_impl },
  { BER_CLASS_CON, 305, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_ServiceID_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_ODisconnectRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              ODisconnectRes_set, hf_index, ett_ansi_map_ODisconnectRes);

  return offset;
}
static int dissect_oDisconnectRes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_ODisconnectRes(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_oDisconnectRes);
}


static const ber_sequence_t CallRecoveryID_set[] = {
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_billingID_impl },
  { BER_CLASS_CON, 275, BER_FLAGS_IMPLTAG, dissect_timeDateOffset_impl },
  { BER_CLASS_CON, 309, BER_FLAGS_IMPLTAG, dissect_timeOfDay_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_CallRecoveryID(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              CallRecoveryID_set, hf_index, ett_ansi_map_CallRecoveryID);

  return offset;
}
static int dissect_CallRecoveryIDList_item_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_CallRecoveryID(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_CallRecoveryIDList_item);
}


static const ber_sequence_t CallRecoveryIDList_set_of[1] = {
  { BER_CLASS_CON, 303, BER_FLAGS_IMPLTAG, dissect_CallRecoveryIDList_item_impl },
};

static int
dissect_ansi_map_CallRecoveryIDList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 CallRecoveryIDList_set_of, hf_index, ett_ansi_map_CallRecoveryIDList);

  return offset;
}
static int dissect_callRecoveryIDList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_CallRecoveryIDList(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_callRecoveryIDList);
}


static const ber_sequence_t CallRecoveryReport_set[] = {
  { BER_CLASS_CON, 304, BER_FLAGS_IMPLTAG, dissect_callRecoveryIDList_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_CallRecoveryReport(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              CallRecoveryReport_set, hf_index, ett_ansi_map_CallRecoveryReport);

  return offset;
}
static int dissect_callRecoveryReport(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_CallRecoveryReport(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_callRecoveryReport);
}


static const ber_sequence_t TAnswer_set[] = {
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_billingID_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_electronicSerialNumber_impl },
  { BER_CLASS_CON, 21, BER_FLAGS_IMPLTAG, dissect_mscid_impl },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_msid },
  { BER_CLASS_CON, 275, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_timeDateOffset_impl },
  { BER_CLASS_CON, 309, BER_FLAGS_IMPLTAG, dissect_timeOfDay_impl },
  { BER_CLASS_CON, 123, BER_FLAGS_IMPLTAG, dissect_transactionCapability_impl },
  { BER_CLASS_CON, 279, BER_FLAGS_IMPLTAG, dissect_triggerType_impl },
  { BER_CLASS_CON, 280, BER_FLAGS_IMPLTAG, dissect_winCapability_impl },
  { BER_CLASS_CON, 33, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_locationAreaID_impl },
  { BER_CLASS_CON, 93, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mobileDirectoryNumber_impl },
  { BER_CLASS_CON, 306, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_featureIndicator_impl },
  { BER_CLASS_CON, 94, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mSCIdentificationNumber_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_servingCellID_impl },
  { BER_CLASS_CON, 22, BER_FLAGS_IMPLTAG, dissect_systemMyTypeCode_impl },
  { BER_CLASS_CON, 119, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_terminationAccessType_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_TAnswer(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              TAnswer_set, hf_index, ett_ansi_map_TAnswer);

  return offset;
}
static int dissect_tAnswer(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_TAnswer(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_tAnswer);
}


static const ber_sequence_t TDisconnect_set[] = {
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_billingID_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_electronicSerialNumber_impl },
  { BER_CLASS_CON, 21, BER_FLAGS_IMPLTAG, dissect_mscid_impl },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_msid },
  { BER_CLASS_CON, 275, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_timeDateOffset_impl },
  { BER_CLASS_CON, 309, BER_FLAGS_IMPLTAG, dissect_timeOfDay_impl },
  { BER_CLASS_CON, 279, BER_FLAGS_IMPLTAG, dissect_triggerType_impl },
  { BER_CLASS_CON, 80, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyNumberDigits1_impl },
  { BER_CLASS_CON, 81, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyNumberDigits2_impl },
  { BER_CLASS_CON, 33, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_locationAreaID_impl },
  { BER_CLASS_CON, 93, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mobileDirectoryNumber_impl },
  { BER_CLASS_CON, 94, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mSCIdentificationNumber_impl },
  { BER_CLASS_CON, 308, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_releaseCause_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_servingCellID_impl },
  { BER_CLASS_CON, 22, BER_FLAGS_IMPLTAG, dissect_systemMyTypeCode_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_TDisconnect(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              TDisconnect_set, hf_index, ett_ansi_map_TDisconnect);

  return offset;
}
static int dissect_tDisconnect(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_TDisconnect(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_tDisconnect);
}


static const ber_sequence_t TDisconnectRes_set[] = {
  { BER_CLASS_CON, 305, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_ServiceID_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_TDisconnectRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              TDisconnectRes_set, hf_index, ett_ansi_map_TDisconnectRes);

  return offset;
}
static int dissect_tDisconnectRes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_TDisconnectRes(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_tDisconnectRes);
}


static const ber_sequence_t UnreliableCallData_set[] = {
  { BER_CLASS_CON, 307, BER_FLAGS_IMPLTAG, dissect_controlNetworkID_impl },
  { BER_CLASS_CON, 21, BER_FLAGS_IMPLTAG, dissect_mscid_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_UnreliableCallData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              UnreliableCallData_set, hf_index, ett_ansi_map_UnreliableCallData);

  return offset;
}
static int dissect_unreliableCallData(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_UnreliableCallData(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_unreliableCallData);
}


static const ber_sequence_t OCalledPartyBusy_set[] = {
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_billingID_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_electronicSerialNumber_impl },
  { BER_CLASS_CON, 21, BER_FLAGS_IMPLTAG, dissect_mscid_impl },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_msid },
  { BER_CLASS_CON, 123, BER_FLAGS_IMPLTAG, dissect_transactionCapability_impl },
  { BER_CLASS_CON, 279, BER_FLAGS_IMPLTAG, dissect_triggerType_impl },
  { BER_CLASS_CON, 280, BER_FLAGS_IMPLTAG, dissect_winCapability_impl },
  { BER_CLASS_CON, 243, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyName_impl },
  { BER_CLASS_CON, 80, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyNumberDigits1_impl },
  { BER_CLASS_CON, 81, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyNumberDigits2_impl },
  { BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartySubaddress_impl },
  { BER_CLASS_CON, 86, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_carrierDigits_impl },
  { BER_CLASS_CON, 87, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_destinationDigits_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_digits_impl },
  { BER_CLASS_CON, 387, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_failureCause_impl },
  { BER_CLASS_CON, 33, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_locationAreaID_impl },
  { BER_CLASS_CON, 93, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mobileDirectoryNumber_impl },
  { BER_CLASS_CON, 94, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mSCIdentificationNumber_impl },
  { BER_CLASS_CON, 32, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pc_ssn_impl },
  { BER_CLASS_CON, 100, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectingNumberDigits_impl },
  { BER_CLASS_CON, 245, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectingPartyName_impl },
  { BER_CLASS_CON, 150, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_routingDigits_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_servingCellID_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_OCalledPartyBusy(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              OCalledPartyBusy_set, hf_index, ett_ansi_map_OCalledPartyBusy);

  return offset;
}
static int dissect_oCalledPartyBusy(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_OCalledPartyBusy(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_oCalledPartyBusy);
}


static const ber_sequence_t OCalledPartyBusyRes_set[] = {
  { BER_CLASS_CON, 128, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_actionCode_impl },
  { BER_CLASS_CON, 130, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_announcementList_impl },
  { BER_CLASS_CON, 86, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_carrierDigits_impl },
  { BER_CLASS_CON, 140, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_AccountCodeDigits_impl },
  { BER_CLASS_CON, 141, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_AlternateBillingDigits_impl },
  { BER_CLASS_CON, 142, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_BillingDigits_impl },
  { BER_CLASS_CON, 311, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_ChargeInformation_impl },
  { BER_CLASS_CON, 88, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_RedirectionIndicator_impl },
  { BER_CLASS_CON, 305, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_ServiceID_impl },
  { BER_CLASS_CON, 96, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_noAnswerTime_impl },
  { BER_CLASS_CON, 97, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_oneTimeFeatureIndicator_impl },
  { BER_CLASS_CON, 147, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_preferredLanguageIndicator_impl },
  { BER_CLASS_CON, 100, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectingNumberDigits_impl },
  { BER_CLASS_CON, 150, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_routingDigits_impl },
  { BER_CLASS_CON, 120, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_terminationList_impl },
  { BER_CLASS_CON, 276, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_triggerAddressList_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_OCalledPartyBusyRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              OCalledPartyBusyRes_set, hf_index, ett_ansi_map_OCalledPartyBusyRes);

  return offset;
}
static int dissect_oCalledPartyBusyRes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_OCalledPartyBusyRes(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_oCalledPartyBusyRes);
}


static const ber_sequence_t ONoAnswer_set[] = {
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_billingID_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_electronicSerialNumber_impl },
  { BER_CLASS_CON, 21, BER_FLAGS_IMPLTAG, dissect_mscid_impl },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_msid },
  { BER_CLASS_CON, 123, BER_FLAGS_IMPLTAG, dissect_transactionCapability_impl },
  { BER_CLASS_CON, 279, BER_FLAGS_IMPLTAG, dissect_triggerType_impl },
  { BER_CLASS_CON, 280, BER_FLAGS_IMPLTAG, dissect_winCapability_impl },
  { BER_CLASS_CON, 243, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyName_impl },
  { BER_CLASS_CON, 80, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyNumberDigits1_impl },
  { BER_CLASS_CON, 81, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyNumberDigits2_impl },
  { BER_CLASS_CON, 84, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartySubaddress_impl },
  { BER_CLASS_CON, 86, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_carrierDigits_impl },
  { BER_CLASS_CON, 87, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_destinationDigits_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_digits_impl },
  { BER_CLASS_CON, 33, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_locationAreaID_impl },
  { BER_CLASS_CON, 93, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mobileDirectoryNumber_impl },
  { BER_CLASS_CON, 94, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mSCIdentificationNumber_impl },
  { BER_CLASS_CON, 32, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pc_ssn_impl },
  { BER_CLASS_CON, 100, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectingNumberDigits_impl },
  { BER_CLASS_CON, 245, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectingPartyName_impl },
  { BER_CLASS_CON, 150, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_routingDigits_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_servingCellID_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_ONoAnswer(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              ONoAnswer_set, hf_index, ett_ansi_map_ONoAnswer);

  return offset;
}
static int dissect_oNoAnswer(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_ONoAnswer(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_oNoAnswer);
}


static const ber_sequence_t ONoAnswerRes_set[] = {
  { BER_CLASS_CON, 128, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_actionCode_impl },
  { BER_CLASS_CON, 130, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_announcementList_impl },
  { BER_CLASS_CON, 86, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_carrierDigits_impl },
  { BER_CLASS_CON, 140, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_AccountCodeDigits_impl },
  { BER_CLASS_CON, 141, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_AlternateBillingDigits_impl },
  { BER_CLASS_CON, 142, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_BillingDigits_impl },
  { BER_CLASS_CON, 311, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_ChargeInformation_impl },
  { BER_CLASS_CON, 88, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_RedirectionIndicator_impl },
  { BER_CLASS_CON, 305, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_ServiceID_impl },
  { BER_CLASS_CON, 96, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_noAnswerTime_impl },
  { BER_CLASS_CON, 97, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_oneTimeFeatureIndicator_impl },
  { BER_CLASS_CON, 147, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_preferredLanguageIndicator_impl },
  { BER_CLASS_CON, 100, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectingNumberDigits_impl },
  { BER_CLASS_CON, 150, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_routingDigits_impl },
  { BER_CLASS_CON, 120, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_terminationList_impl },
  { BER_CLASS_CON, 276, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_triggerAddressList_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_ONoAnswerRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              ONoAnswerRes_set, hf_index, ett_ansi_map_ONoAnswerRes);

  return offset;
}
static int dissect_oNoAnswerRes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_ONoAnswerRes(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_oNoAnswerRes);
}



static int
dissect_ansi_map_PositionInformationCode(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_positionInformationCode_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_PositionInformationCode(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_positionInformationCode);
}


static const ber_sequence_t PositionRequest_set[] = {
  { BER_CLASS_CON, 21, BER_FLAGS_IMPLTAG, dissect_mscid_impl },
  { BER_CLASS_CON, 315, BER_FLAGS_IMPLTAG, dissect_positionInformationCode_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_electronicSerialNumber_impl },
  { BER_CLASS_CON, 93, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mobileDirectoryNumber_impl },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_msid },
  { BER_CLASS_CON, 103, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_senderIdentificationNumber_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_PositionRequest(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              PositionRequest_set, hf_index, ett_ansi_map_PositionRequest);

  return offset;
}
static int dissect_positionRequest(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_PositionRequest(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_positionRequest);
}



static int
dissect_ansi_map_MSStatus(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_mSStatus_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_MSStatus(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_mSStatus);
}


static const ber_sequence_t PositionRequestRes_set[] = {
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_electronicSerialNumber_impl },
  { BER_CLASS_CON, 53, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extendedMSCID_impl },
  { BER_CLASS_CON, 94, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mSCIdentificationNumber_impl },
  { BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mscid_impl },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_msid },
  { BER_CLASS_CON, 313, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mSStatus_impl },
  { BER_CLASS_CON, 32, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pc_ssn_impl },
  { BER_CLASS_CON, 202, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pSID_RSIDInformation_impl },
  { BER_CLASS_CON, 33, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_locationAreaID_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_servingCellID_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_PositionRequestRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              PositionRequestRes_set, hf_index, ett_ansi_map_PositionRequestRes);

  return offset;
}
static int dissect_positionRequestRes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_PositionRequestRes(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_positionRequestRes);
}


static const ber_sequence_t PositionRequestForward_set[] = {
  { BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_interMSCCircuitID_impl },
  { BER_CLASS_CON, 315, BER_FLAGS_IMPLTAG, dissect_positionInformationCode_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_electronicSerialNumber_impl },
  { BER_CLASS_CON, 242, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_imsi_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mobileIdentificationNumber_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_PositionRequestForward(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              PositionRequestForward_set, hf_index, ett_ansi_map_PositionRequestForward);

  return offset;
}
static int dissect_positionRequestForward(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_PositionRequestForward(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_positionRequestForward);
}


static const ber_sequence_t PositionRequestForwardRes_set[] = {
  { BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mscid_impl },
  { BER_CLASS_CON, 313, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mSStatus_impl },
  { BER_CLASS_CON, 33, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_locationAreaID_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_servingCellID_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_PositionRequestForwardRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              PositionRequestForwardRes_set, hf_index, ett_ansi_map_PositionRequestForwardRes);

  return offset;
}
static int dissect_positionRequestForwardRes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_PositionRequestForwardRes(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_positionRequestForwardRes);
}



static int
dissect_ansi_map_ControlType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_controlType_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_ControlType(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_controlType);
}


static const value_string ansi_map_GapDuration_vals[] = {
  {   0, "not-used" },
  { 0, NULL }
};


static int
dissect_ansi_map_GapDuration(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_gapDuration_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_GapDuration(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_gapDuration);
}


static const value_string ansi_map_SCFOverloadGapInterval_vals[] = {
  {   0, "not-used" },
  { 0, NULL }
};


static int
dissect_ansi_map_SCFOverloadGapInterval(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_sCFOverloadGapInterval_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_SCFOverloadGapInterval(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_sCFOverloadGapInterval);
}


static const value_string ansi_map_ServiceManagementSystemGapInterval_vals[] = {
  {   0, "not-used" },
  { 0, NULL }
};


static int
dissect_ansi_map_ServiceManagementSystemGapInterval(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_serviceManagementSystemGapInterval_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_ServiceManagementSystemGapInterval(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_serviceManagementSystemGapInterval);
}


static const value_string ansi_map_GapInterval_vals[] = {
  { 343, "sCFOverloadGapInterval" },
  { 344, "serviceManagementSystemGapInterval" },
  { 0, NULL }
};

static const ber_choice_t GapInterval_choice[] = {
  { 343, BER_CLASS_CON, 343, BER_FLAGS_IMPLTAG, dissect_sCFOverloadGapInterval_impl },
  { 344, BER_CLASS_CON, 344, BER_FLAGS_IMPLTAG, dissect_serviceManagementSystemGapInterval_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_ansi_map_GapInterval(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 GapInterval_choice, hf_index, ett_ansi_map_GapInterval,
                                 NULL);

  return offset;
}
static int dissect_gapInterval(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_GapInterval(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_gapInterval);
}


static const ber_sequence_t ACGDirective_set[] = {
  { BER_CLASS_CON, 341, BER_FLAGS_IMPLTAG, dissect_controlType_impl },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_destinationAddress },
  { BER_CLASS_CON, 342, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gapDuration_impl },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_gapInterval },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_ACGDirective(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              ACGDirective_set, hf_index, ett_ansi_map_ACGDirective);

  return offset;
}
static int dissect_aCGDirective(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_ACGDirective(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_aCGDirective);
}



static int
dissect_ansi_map_InvokingNEType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_invokingNEType_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_InvokingNEType(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_invokingNEType);
}



static int
dissect_ansi_map_Range(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_range_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_Range(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_range);
}


static const ber_sequence_t RoamerDatabaseVerificationRequest_set[] = {
  { BER_CLASS_CON, 353, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_invokingNEType_impl },
  { BER_CLASS_CON, 93, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mobileDirectoryNumber_impl },
  { BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mscid_impl },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_msid },
  { BER_CLASS_CON, 352, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_range_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_RoamerDatabaseVerificationRequest(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              RoamerDatabaseVerificationRequest_set, hf_index, ett_ansi_map_RoamerDatabaseVerificationRequest);

  return offset;
}
static int dissect_roamerDatabaseVerificationRequest(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_RoamerDatabaseVerificationRequest(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_roamerDatabaseVerificationRequest);
}


static const ber_sequence_t RoamerDatabaseVerificationRequestRes_set[] = {
  { BER_CLASS_CON, 123, BER_FLAGS_IMPLTAG, dissect_transactionCapability_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_RoamerDatabaseVerificationRequestRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              RoamerDatabaseVerificationRequestRes_set, hf_index, ett_ansi_map_RoamerDatabaseVerificationRequestRes);

  return offset;
}
static int dissect_roamerDatabaseVerificationRequestRes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_RoamerDatabaseVerificationRequestRes(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_roamerDatabaseVerificationRequestRes);
}


static const ber_sequence_t AddService_set[] = {
  { BER_CLASS_CON, 212, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaConnectionReferenceList_impl },
  { BER_CLASS_CON, 176, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaServiceOptionList_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_digits_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_interMSCCircuitID_impl },
  { BER_CLASS_CON, 242, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_imsi_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mobileIdentificationNumber_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_AddService(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              AddService_set, hf_index, ett_ansi_map_AddService);

  return offset;
}
static int dissect_addService(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_AddService(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_addService);
}


static const ber_sequence_t AddServiceRes_set[] = {
  { BER_CLASS_CON, 212, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaConnectionReferenceList_impl },
  { BER_CLASS_CON, 176, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaServiceOptionList_impl },
  { BER_CLASS_CON, 348, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_qosPriority_impl },
  { BER_CLASS_CON, 218, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_reasonList_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_AddServiceRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              AddServiceRes_set, hf_index, ett_ansi_map_AddServiceRes);

  return offset;
}
static int dissect_addServiceRes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_AddServiceRes(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_addServiceRes);
}


static const ber_sequence_t DropService_set[] = {
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_billingID_impl },
  { BER_CLASS_CON, 212, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaConnectionReferenceList_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_interMSCCircuitID_impl },
  { BER_CLASS_CON, 242, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_imsi_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mobileIdentificationNumber_impl },
  { BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_releaseReason_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_DropService(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              DropService_set, hf_index, ett_ansi_map_DropService);

  return offset;
}
static int dissect_dropService(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_DropService(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_dropService);
}


static const ber_sequence_t DropServiceRes_set[] = {
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_billingID_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_DropServiceRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              DropServiceRes_set, hf_index, ett_ansi_map_DropServiceRes);

  return offset;
}
static int dissect_dropServiceRes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_DropServiceRes(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_dropServiceRes);
}



static int
dissect_ansi_map_AKeyProtocolVersion(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_aKeyProtocolVersion_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_AKeyProtocolVersion(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_aKeyProtocolVersion);
}



static int
dissect_ansi_map_MobileStationPartialKey(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_mobileStationPartialKey_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_MobileStationPartialKey(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_mobileStationPartialKey);
}


static const value_string ansi_map_NewlyAssignedMSID_vals[] = {
  { 187, "newlyAssignedMIN" },
  { 287, "newlyAssignedIMSI" },
  { 0, NULL }
};

static const ber_choice_t NewlyAssignedMSID_choice[] = {
  { 187, BER_CLASS_CON, 187, BER_FLAGS_IMPLTAG, dissect_newlyAssignedMIN_impl },
  { 287, BER_CLASS_CON, 287, BER_FLAGS_IMPLTAG, dissect_newlyAssignedIMSI_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_ansi_map_NewlyAssignedMSID(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 NewlyAssignedMSID_choice, hf_index, ett_ansi_map_NewlyAssignedMSID,
                                 NULL);

  return offset;
}
static int dissect_newlyAssignedMSID(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_NewlyAssignedMSID(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_newlyAssignedMSID);
}


static const ber_sequence_t OTASPRequest_set[] = {
  { BER_CLASS_CON, 128, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ctionCode_impl },
  { BER_CLASS_CON, 181, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_aKeyProtocolVersion_impl },
  { BER_CLASS_CON, 161, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_authenticationData_impl },
  { BER_CLASS_CON, 35, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_authenticationResponse_impl },
  { BER_CLASS_CON, 38, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callHistoryCount_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_electronicSerialNumber_impl },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_msid },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_mobileStationMSID },
  { BER_CLASS_CON, 185, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mobileStationPartialKey_impl },
  { BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mscid_impl },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_newlyAssignedMSID },
  { BER_CLASS_CON, 40, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_randomVariable_impl },
  { BER_CLASS_CON, 41, BER_FLAGS_IMPLTAG, dissect_randomVariableBaseStation_impl },
  { BER_CLASS_CON, 193, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_serviceIndicator_impl },
  { BER_CLASS_CON, 49, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_systemCapabilities_impl },
  { BER_CLASS_CON, 47, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_terminalType_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_OTASPRequest(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              OTASPRequest_set, hf_index, ett_ansi_map_OTASPRequest);

  return offset;
}
static int dissect_oTASPRequest(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_OTASPRequest(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_oTASPRequest);
}



static int
dissect_ansi_map_BaseStationPartialKey(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_baseStationPartialKey_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_BaseStationPartialKey(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_baseStationPartialKey);
}



static int
dissect_ansi_map_ModulusValue(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_modulusValue_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_ModulusValue(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_modulusValue);
}



static int
dissect_ansi_map_OTASP_ResultCode(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_otasp_ResultCode_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_OTASP_ResultCode(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_otasp_ResultCode);
}



static int
dissect_ansi_map_PrimitiveValue(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_primitiveValue_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_PrimitiveValue(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_primitiveValue);
}


static const ber_sequence_t OTASPRequestRes_set[] = {
  { BER_CLASS_CON, 181, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_aKeyProtocolVersion_impl },
  { BER_CLASS_CON, 36, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_authenticationResponseBaseStation_impl },
  { BER_CLASS_CON, 183, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_baseStationPartialKey_impl },
  { BER_CLASS_CON, 50, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_denyAccess_impl },
  { BER_CLASS_CON, 186, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_modulusValue_impl },
  { BER_CLASS_CON, 189, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_otasp_ResultCode_impl },
  { BER_CLASS_CON, 190, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_primitiveValue_impl },
  { BER_CLASS_CON, 194, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_signalingMessageEncryptionReport_impl },
  { BER_CLASS_CON, 156, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ssdUpdateReport_impl },
  { BER_CLASS_CON, 124, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_uniqueChallengeReport_impl },
  { BER_CLASS_CON, 196, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_voicePrivacyReport_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_OTASPRequestRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              OTASPRequestRes_set, hf_index, ett_ansi_map_OTASPRequestRes);

  return offset;
}
static int dissect_oTASPRequestRes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ansi_map_OTASPRequestRes(FALSE, tvb, offset, pinfo, tree, hf_ansi_map_oTASPRequestRes);
}



static int
dissect_ansi_map_FaultyParameter(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t Profile_set[] = {
  { BER_CLASS_CON, 78, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_authenticationCapability_impl },
  { BER_CLASS_CON, 25, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingFeaturesIndicator_impl },
  { BER_CLASS_CON, 86, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_carrierDigits_impl },
  { BER_CLASS_CON, 176, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cdmaServiceOptionList_impl },
  { BER_CLASS_CON, 307, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_controlNetworkID_impl },
  { BER_CLASS_CON, 140, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_AccountCodeDigits_impl },
  { BER_CLASS_CON, 141, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_AlternateBillingDigits_impl },
  { BER_CLASS_CON, 142, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dmh_BillingDigits_impl },
  { BER_CLASS_CON, 143, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_geographicAuthorization_impl },
  { BER_CLASS_CON, 92, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_messageWaitingNotificationCount_impl },
  { BER_CLASS_CON, 289, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_messageWaitingNotificationType_impl },
  { BER_CLASS_CON, 93, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mobileDirectoryNumber_impl },
  { BER_CLASS_CON, 23, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_originationIndicator_impl },
  { BER_CLASS_CON, 98, BER_FLAGS_IMPLTAG, dissect_originationTriggers_impl },
  { BER_CLASS_CON, 274, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pACAIndicator_impl },
  { BER_CLASS_CON, 147, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_preferredLanguageIndicator_impl },
  { BER_CLASS_CON, 348, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_qosPriority_impl },
  { BER_CLASS_CON, 227, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_restrictionDigits_impl },
  { BER_CLASS_CON, 150, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_routingDigits_impl },
  { BER_CLASS_CON, 203, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pSID_RSIDList_impl },
  { BER_CLASS_CON, 115, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sms_OriginationRestrictions_impl },
  { BER_CLASS_CON, 117, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sms_TerminationRestrictions_impl },
  { BER_CLASS_CON, 154, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_spinipin_impl },
  { BER_CLASS_CON, 155, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_spiniTriggers_impl },
  { BER_CLASS_CON, 221, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tdmaDataFeaturesIndicator_impl },
  { BER_CLASS_CON, 24, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_terminationRestrictionCode_impl },
  { BER_CLASS_CON, 122, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_terminationTriggers_impl },
  { BER_CLASS_CON, 276, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_triggerAddressList_impl },
  { BER_CLASS_CON, 208, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_userGroup_impl },
  { BER_CLASS_CON, 200, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_nonPublicData_impl },
  { BER_CLASS_CON, 209, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_userZoneData_impl },
  { BER_CLASS_CON, 355, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyCategory_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_Profile(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              Profile_set, hf_index, ett_ansi_map_Profile);

  return offset;
}



static int
dissect_ansi_map_CDMABandClassInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_ansi_map_CDMABandClassList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t SRFCapability_set[] = {
  { BER_CLASS_CON, 274, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_specializedResource_impl },
  { BER_CLASS_CON, 383, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_privateSpecializedResource_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_SRFCapability(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              SRFCapability_set, hf_index, ett_ansi_map_SRFCapability);

  return offset;
}


static const ber_sequence_t InvokeData_sequence[] = {
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_handoffMeasurementRequest },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_facilitiesDirective },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_handoffBack },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_facilitiesRelease },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_qualificationRequest },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_qualificationDirective },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_blocking },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_unblocking },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_resetCircuit },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_trunkTest },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_trunkTestDisconnect },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_registrationNotification },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_registrationCancellation },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_locationRequest },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_routingRequest },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_featureRequest },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_unreliableRoamerDataDirective },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_mSInactive },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_transferToNumberRequest },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_redirectionRequest },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_handoffToThird },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_flashRequest },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_authenticationDirective },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_authenticationRequest },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_baseStationChallenge },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_authenticationFailureReport },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_countRequest },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_interSystemPage },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_unsolicitedResponse },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_bulkDeregistration },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_handoffMeasurementRequest2 },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_facilitiesDirective2 },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_handoffBack2 },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_handoffToThird2 },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_authenticationDirectiveForward },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_authenticationStatusReport },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_informationDirective },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_informationForward },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_interSystemAnswer },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_interSystemPage2 },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_interSystemSetup },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_originationRequest },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_randomVariableRequest },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_redirectionDirective },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_remoteUserInteractionDirective },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_sMSDeliveryBackward },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_sMSDeliveryForward },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_sMSDeliveryPointToPoint },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_sMSNotification },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_sMSRequest },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_oTASPRequest },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_changeFacilities },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_changeService },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_parameterRequest },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_tMSIDirective },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_serviceRequest },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_analyzedInformation },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_connectionFailureReport },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_connectResource },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_facilitySelectedAndAvailable },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_modify },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_search },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_seizeResource },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_sRFDirective },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_tBusy },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_tNoAnswer },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_messageDirective },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_bulkDisconnection },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_callControlDirective },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_oAnswer },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_oDisconnect },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_callRecoveryReport },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_tAnswer },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_tDisconnect },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_unreliableCallData },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_oCalledPartyBusy },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_oNoAnswer },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_positionRequest },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_positionRequestForward },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_aCGDirective },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_roamerDatabaseVerificationRequest },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_addService },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_dropService },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_InvokeData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   InvokeData_sequence, hf_index, ett_ansi_map_InvokeData);

  return offset;
}


static const ber_sequence_t ReturnData_sequence[] = {
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_handoffMeasurementRequestRes },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_facilitiesDirectiveRes },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_handoffBackRes },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_facilitiesReleaseRes },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_qualificationRequestRes },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_resetCircuitRes },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_registrationNotificationRes },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_registrationCancellationRes },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_locationRequestRes },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_routingRequestRes },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_featureRequestRes },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_transferToNumberRequestRes },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_handoffToThirdRes },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_authenticationDirectiveRes },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_authenticationRequestRes },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_authenticationFailureReportRes },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_countRequestRes },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_interSystemPageRes },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_unsolicitedResponseRes },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_handoffMeasurementRequest2Res },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_facilitiesDirective2Res },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_handoffBack2Res },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_handoffToThird2Res },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_authenticationDirectiveForwardRes },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_authenticationStatusReportRes },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_informationForwardRes },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_interSystemPage2Res },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_interSystemSetupRes },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_originationRequestRes },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_randomVariableRequestRes },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_remoteUserInteractionDirectiveRes },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_sMSDeliveryBackwardRes },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_sMSDeliveryForwardRes },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_sMSDeliveryPointToPointRes },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_sMSNotificationRes },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_sMSRequestRes },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_oTASPRequestRes },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_changeFacilitiesRes },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_changeServiceRes },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_parameterRequestRes },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_tMSIDirectiveRes },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_serviceRequestRes },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_analyzedInformationRes },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_facilitySelectedAndAvailableRes },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_modifyRes },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_searchRes },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_seizeResourceRes },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_sRFDirectiveRes },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_tBusyRes },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_tNoAnswerRes },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_callControlDirectiveRes },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_oDisconnectRes },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_tDisconnectRes },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_oCalledPartyBusyRes },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_oNoAnswerRes },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_positionRequestRes },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_positionRequestForwardRes },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_roamerDatabaseVerificationRequestRes },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_addServiceRes },
  { BER_CLASS_PRI, 18, BER_FLAGS_NOOWNTAG, dissect_dropServiceRes },
  { 0, 0, 0, NULL }
};

static int
dissect_ansi_map_ReturnData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ReturnData_sequence, hf_index, ett_ansi_map_ReturnData);

  return offset;
}

/*--- PDUs ---*/

static void dissect_AuthenticationDirective_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_ansi_map_AuthenticationDirective(FALSE, tvb, 0, pinfo, tree, hf_ansi_map_AuthenticationDirective_PDU);
}
static void dissect_AuthenticationDirectiveRes_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_ansi_map_AuthenticationDirectiveRes(FALSE, tvb, 0, pinfo, tree, hf_ansi_map_AuthenticationDirectiveRes_PDU);
}
static void dissect_OriginationRequest_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_ansi_map_OriginationRequest(FALSE, tvb, 0, pinfo, tree, hf_ansi_map_OriginationRequest_PDU);
}
static void dissect_OriginationRequestRes_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_ansi_map_OriginationRequestRes(FALSE, tvb, 0, pinfo, tree, hf_ansi_map_OriginationRequestRes_PDU);
}


/*--- End of included file: packet-ansi_map-fn.c ---*/
#line 3439 "packet-ansi_map-template.c"

static int dissect_invokeData(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {


  switch(OperationCode){
   case 1: /*Handoff Measurement Request*/
	   offset = dissect_ansi_map_HandoffMeasurementRequest(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_handoffMeasurementRequest);
	   break;
   case 2: /*Facilities Directive*/
	   offset = dissect_ansi_map_FacilitiesDirective(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_facilitiesDirective);
	   break;
   case 3: /*Mobile On Channel*/
	   proto_tree_add_text(tree, tvb, offset, -1, "Unknown invokeData blob");
	   break;
   case 4: /*Handoff Back*/
	   offset = dissect_ansi_map_HandoffBack(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_handoffBack);
	   break;
   case 5: /*Facilities Release*/
	   offset = dissect_ansi_map_FacilitiesRelease(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_facilitiesRelease);
	   break;
   case 6: /*Qualification Request*/
	   offset = dissect_ansi_map_QualificationRequest(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_qualificationRequest);
	   break;
   case 7: /*Qualification Directive*/
	   offset = dissect_ansi_map_QualificationDirective(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_qualificationDirective);
	   break;
   case 8: /*Blocking*/
	   offset = dissect_ansi_map_Blocking(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_blocking);
	   break;
   case 9: /*Unblocking*/
	   offset = dissect_ansi_map_Unblocking(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_unblocking);
	   break;
   case 10: /*Reset Circuit*/
	   offset = dissect_ansi_map_ResetCircuit(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_resetCircuit);
	   break;
   case 11: /*Trunk Test*/
	   offset = dissect_ansi_map_TrunkTest(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_trunkTest);
	   break;
   case 12: /*Trunk Test Disconnect*/
	  offset = dissect_ansi_map_TrunkTestDisconnect(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_trunkTestDisconnect);
	  break;
   case  13: /*Registration Notification*/
	  offset = dissect_ansi_map_RegistrationNotification(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_registrationNotification);
	  break;
   case  14: /*Registration Cancellation*/
	   offset = dissect_ansi_map_RegistrationCancellation(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_registrationCancellation);
	  break;
   case  15: /*Location Request*/
	   offset = dissect_ansi_map_LocationRequest(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_locationRequest);
	   break;
   case  16: /*Routing Request*/
	   offset = dissect_ansi_map_RoutingRequest(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_routingRequest);
	   break;
   case  17: /*Feature Request*/
	   offset = dissect_ansi_map_FeatureRequest(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_featureRequest);
	   break;
   case  18: /*Reserved 18 (Service Profile Request, IS-41-C)*/
	   proto_tree_add_text(tree, tvb, offset, -1, "Unknown invokeData blob(18 (Service Profile Request, IS-41-C)");
	   break;
   case  19: /*Reserved 19 (Service Profile Directive, IS-41-C)*/
	   proto_tree_add_text(tree, tvb, offset, -1, "Unknown invokeData blob(19 Service Profile Directive, IS-41-C)");
	   break;
   case  20: /*Unreliable Roamer Data Directive*/
	   offset = dissect_ansi_map_UnreliableRoamerDataDirective(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_unreliableRoamerDataDirective);
	   break;
   case  21: /*Reserved 21 (Call Data Request, IS-41-C)*/
	   proto_tree_add_text(tree, tvb, offset, -1, "Unknown invokeData blob(Reserved 21 (Call Data Request, IS-41-C)");
	   break;
   case  22: /*MS Inactive*/
	   offset = dissect_ansi_map_MSInactive(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_mSInactive);
	   break;
   case  23: /*Transfer To Number Request*/
	   offset = dissect_ansi_map_TransferToNumberRequest(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_transferToNumberRequest);
	   break;
   case  24: /*Redirection Request*/
	   offset = dissect_ansi_map_RedirectionRequest(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_redirectionRequest);
	   break;
   case  25: /*Handoff To Third*/
	   offset = dissect_ansi_map_HandoffToThird(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_handoffToThird);
	   break;
   case  26: /*Flash Request*/
	   offset = dissect_ansi_map_FlashRequest(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_flashRequest);
	   break;
   case  27: /*Authentication Directive*/
	   offset = dissect_ansi_map_AuthenticationDirective(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_authenticationDirective);
	   break;
   case  28: /*Authentication Request*/
	   offset = dissect_ansi_map_AuthenticationRequest(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_authenticationRequest);
	   break;
   case  29: /*Base Station Challenge*/
	   offset = dissect_ansi_map_BaseStationChallenge(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_baseStationChallenge);
	   break;
   case  30: /*Authentication Failure Report*/
	   offset = dissect_ansi_map_AuthenticationFailureReport(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_authenticationFailureReport);
	   break;
   case  31: /*Count Request*/
	   offset = dissect_ansi_map_CountRequest(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_countRequest);
	   break;
   case  32: /*Inter System Page*/
	   offset = dissect_ansi_map_InterSystemPage(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_interSystemPage);
	   break;
   case  33: /*Unsolicited Response*/
	   offset = dissect_ansi_map_UnsolicitedResponse(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_unsolicitedResponse);
	   break;
   case  34: /*Bulk Deregistration*/
	   offset = dissect_ansi_map_BulkDeregistration(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_bulkDeregistration);
	   break;
   case  35: /*Handoff Measurement Request 2*/
	   offset = dissect_ansi_map_HandoffMeasurementRequest2(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_handoffMeasurementRequest2);
	   break;
   case  36: /*Facilities Directive 2*/
	   offset = dissect_ansi_map_FacilitiesDirective2(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_facilitiesDirective2);
	   break;
   case  37: /*Handoff Back 2*/
	   offset = dissect_ansi_map_HandoffBack2(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_handoffBack2);
	   break;
   case  38: /*Handoff To Third 2*/
	   offset = dissect_ansi_map_HandoffToThird2(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_handoffToThird2);
	   break;
   case  39: /*Authentication Directive Forward*/
	   offset = dissect_ansi_map_AuthenticationDirectiveForward(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_authenticationDirectiveForward);
	   break;
   case  40: /*Authentication Status Report*/
	   offset = dissect_ansi_map_AuthenticationStatusReport(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_authenticationStatusReport);
	   break;
   case  41: /*Reserved 41*/
	   proto_tree_add_text(tree, tvb, offset, -1, "Reserved 41, Unknown invokeData blob");
	   break;
   case  42: /*Information Directive*/
	   offset = dissect_ansi_map_InformationDirective(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_informationDirective);
	   break;
   case  43: /*Information Forward*/
	   offset = dissect_ansi_map_InformationForward(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_informationForward);
	   break;
   case  44: /*Inter System Answer*/
	   offset = dissect_ansi_map_InterSystemAnswer(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_interSystemAnswer);
	   break;
   case  45: /*Inter System Page 2*/
	   offset = dissect_ansi_map_InterSystemPage2(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_interSystemPage2);
	   break;
   case  46: /*Inter System Setup*/
	   offset = dissect_ansi_map_InterSystemSetup(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_interSystemSetup);
	   break;
  case  47: /*OriginationRequest*/
	  offset = dissect_ansi_map_OriginationRequest(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_originationRequest);
	  break;
  case  48: /*Random Variable Request*/
	  offset = dissect_ansi_map_RandomVariableRequest(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_randomVariableRequest);
	  break;
  case  49: /*Redirection Directive*/
	  offset = dissect_ansi_map_RedirectionDirective(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_redirectionDirective);
	  break;
  case  50: /*Remote User Interaction Directive*/
	  offset = dissect_ansi_map_RemoteUserInteractionDirective(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_remoteUserInteractionDirective);
	  break;
  case  51: /*SMS Delivery Backward*/
	  offset = dissect_ansi_map_SMSDeliveryBackward(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_sMSDeliveryBackward);
	  break;
  case  52: /*SMS Delivery Forward*/
	  offset = dissect_ansi_map_SMSDeliveryForward(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_sMSDeliveryForward);
	  break;
  case  53: /*SMS Delivery Point to Point*/
	  offset = dissect_ansi_map_SMSDeliveryPointToPoint(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_sMSDeliveryPointToPoint);
	  break;
  case  54: /*SMS Notification*/
	  offset = dissect_ansi_map_SMSNotification(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_sMSNotification);
	  break;
  case  55: /*SMS Request*/
	  offset = dissect_ansi_map_SMSRequest(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_sMSRequest);
	  break;
	  /* End N.S0005*/
	  /* N.S0010-0 v 1.0 */
	  /* N.S0011-0 v 1.0 */
  case  56: /*OTASP Request 6.4.2.CC*/
	  offset = dissect_ansi_map_OTASPRequest(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_oTASPRequest);
	  break;
	  /*End N.S0011-0 v 1.0 */
  case  57: /*Information Backward*/
	  offset = offset;
	  break;
	  /*  N.S0008-0 v 1.0 */
  case  58: /*Change Facilities*/
	  offset = dissect_ansi_map_ChangeFacilities(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_changeFacilities);
	  break;
  case  59: /*Change Service*/
	  offset = dissect_ansi_map_ChangeService(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_changeService);
	  break;
	  /* End N.S0008-0 v 1.0 */	
  case  60: /*Parameter Request*/
	  offset = dissect_ansi_map_ParameterRequest(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_parameterRequest);
	  break;
  case  61: /*TMSI Directive*/
	  offset = dissect_ansi_map_TMSIDirective(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_tMSIDirective);
	  break;
	  /*End  N.S0010-0 v 1.0 */
  case  62: /*Reserved 62*/
	  proto_tree_add_text(tree, tvb, offset, -1, "Unknown invokeData blob(Reserved 62)");
	  break;
  case  63: /*Service Request N.S0012-0 v 1.0*/
	  offset = dissect_ansi_map_ServiceRequest(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_serviceRequest);
	  break;
	  /* N.S0013 */
  case  64: /*Analyzed Information Request*/
	  offset = dissect_ansi_map_AnalyzedInformation(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_analyzedInformation);
	  break;
  case  65: /*Connection Failure Report*/
	  offset = dissect_ansi_map_ConnectionFailureReport(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_connectionFailureReport);
	  break;
  case  66: /*Connect Resource*/
	  offset = dissect_ansi_map_ConnectResource(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_connectResource);
	  break;
  case  67: /*Disconnect Resource*/
	  /* No data */
	  break;
  case  68: /*Facility Selected and Available*/
	  offset = dissect_ansi_map_FacilitySelectedAndAvailable(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_facilitySelectedAndAvailable);
	  break;
  case  69: /*Instruction Request*/
	  /* No data */
	  break;
  case  70: /*Modify*/
	  offset = dissect_ansi_map_Modify(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_modify);
	  break;
  case  71: /*Reset Timer*/
	  /*No Data*/
	  break;
  case  72: /*Search*/
	  offset = dissect_ansi_map_Search(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_search);
	  break;
  case  73: /*Seize Resource*/
	  offset = dissect_ansi_map_SeizeResource(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_seizeResource);
	  break;
  case  74: /*SRF Directive*/
	  offset = dissect_ansi_map_SRFDirective(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_sRFDirective);
	  break;
  case  75: /*T Busy*/
	  offset = dissect_ansi_map_TBusy(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_tBusy);
	  break;
  case  76: /*T NoAnswer*/
	  offset = dissect_ansi_map_TNoAnswer(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_tNoAnswer);
	  break;
	  /*END N.S0013 */
  case  77: /*Release*/
	  offset = offset;
	  break;
  case  78: /*SMS Delivery Point to Point Ack*/
	  offset = offset;
	  break;
	  /* N.S0024*/
  case  79: /*Message Directive*/
	  offset = dissect_ansi_map_MessageDirective(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_messageDirective);
	  break;
	  /*END N.S0024*/
	  /* N.S0018 PN-4287*/
  case  80: /*Bulk Disconnection*/
	  offset = dissect_ansi_map_BulkDisconnection(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_bulkDisconnection);
	  break;
  case  81: /*Call Control Directive*/
	  offset = dissect_ansi_map_CallControlDirective(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_callControlDirective);
	  break;
  case  82: /*O Answer*/
	  offset = dissect_ansi_map_OAnswer(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_oAnswer);
	  break;
  case  83: /*O Disconnect*/
	  offset = dissect_ansi_map_ODisconnect(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_oDisconnect);
	  break;
  case  84: /*Call Recovery Report*/
	  offset = dissect_ansi_map_CallRecoveryReport(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_callRecoveryReport);
	  break;
  case  85: /*T Answer*/
	  offset = dissect_ansi_map_TAnswer(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_tAnswer);
	  break;
  case  86: /*T Disconnect*/
	  offset = dissect_ansi_map_TDisconnect(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_tDisconnect);
	  break;
  case  87: /*Unreliable Call Data*/
	  offset = dissect_ansi_map_UnreliableCallData(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_unreliableCallData);
	  break;
	  /* N.S0018 PN-4287*/
	  /*N.S0004 */
  case  88: /*O CalledPartyBusy*/
	  offset = dissect_ansi_map_OCalledPartyBusy(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_oCalledPartyBusy);
	  break;
  case  89: /*O NoAnswer*/
	  offset = dissect_ansi_map_ONoAnswer(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_oNoAnswer);
	  break;
  case  90: /*Position Request*/
	  offset = dissect_ansi_map_PositionRequest(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_positionRequest);
	  break;
  case  91: /*Position Request Forward*/
	  offset = dissect_ansi_map_PositionRequestForward(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_positionRequestForward);
	  break;
	   /*END N.S0004 */
  case  92: /*Call Termination Report*/
	  offset = offset;
	  break;
  case  93: /*Geo Position Directive*/
	  offset = offset;
	  break;
  case  94: /*Geo Position Request*/
	  offset = offset;
	  break;
  case  95: /*Inter System Position Request*/
	  offset = offset;
	  break;
  case  96: /*Inter System Position Request Forward*/
	  offset = offset;
	  break;
	  /* 3GPP2 N.S0023-0 */
  case  97: /*ACG Directive*/
	  offset = dissect_ansi_map_ACGDirective(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_aCGDirective);
	  break;
	  /* END 3GPP2 N.S0023-0 */
  case  98: /*Roamer Database Verification Request*/
	  offset = dissect_ansi_map_RoamerDatabaseVerificationRequest(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_roamerDatabaseVerificationRequest);
	  break;
	  /* N.S0029 */
  case  99: /*Add Service*/
	  offset = dissect_ansi_map_AddService(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_addService);
	  break;
  case  100: /*Drop Service*/
	  offset = dissect_ansi_map_DropService(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_dropService);
	  break;
	  /*End N.S0029 */
  default:
	  proto_tree_add_text(tree, tvb, offset, -1, "Unknown invokeData blob");
	  break;
  }

  return offset;

 }

static int dissect_returnData(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {

  switch(OperationCode){
   case 1: /*Handoff Measurement Request*/
	   offset = dissect_ansi_map_HandoffMeasurementRequestRes(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_handoffMeasurementRequestRes);
	   break;
   case 2: /*Facilities Directive*/
	   offset = dissect_ansi_map_FacilitiesDirectiveRes(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_facilitiesDirectiveRes);
	   break;
   case 4: /*Handoff Back*/
	   offset = dissect_ansi_map_HandoffBackRes(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_handoffBackRes);
	   break;
   case 5: /*Facilities Release*/
	   offset = dissect_ansi_map_FacilitiesReleaseRes(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_facilitiesReleaseRes);
	   break;
  case 6: /*Qualification Request*/
	   offset = dissect_ansi_map_QualificationRequestRes(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_qualificationRequestRes);
	   break;
   case 10: /*Reset Circuit*/
	   offset = dissect_ansi_map_ResetCircuitRes(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_resetCircuitRes);
	   break;
   case 13: /*Registration Notification*/
	  offset = dissect_ansi_map_RegistrationNotificationRes(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_registrationNotificationRes);
	  break;
   case  14: /*Registration Cancellation*/
      offset = dissect_ansi_map_RegistrationCancellationRes(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_registrationCancellationRes);
	  break;
   case  15: /*Location Request*/
	   offset = dissect_ansi_map_LocationRequestRes(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_locationRequestRes);
	   break;
   case  16: /*Routing Request*/
	   offset = dissect_ansi_map_RoutingRequestRes(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_routingRequestRes);
	   break;
   case  17: /*Feature Request*/
	   offset = dissect_ansi_map_FeatureRequestRes(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_featureRequestRes);
	   break;
   case  23: /*Transfer To Number Request*/
	   offset = dissect_ansi_map_TransferToNumberRequestRes(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_transferToNumberRequestRes);
	   break;
   case  25: /*Handoff To Third*/
	   offset = dissect_ansi_map_HandoffToThirdRes(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_handoffToThirdRes);
	   break;
   case  27: /*Authentication Directive*/
	   offset = dissect_ansi_map_AuthenticationDirectiveRes(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_authenticationDirectiveRes);
	   break;
   case  28: /*Authentication Request*/
	   offset = dissect_ansi_map_AuthenticationRequestRes(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_authenticationRequestRes);
	   break;
   case  30: /*Authentication Failure Report*/
	   offset = dissect_ansi_map_AuthenticationFailureReportRes(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_authenticationFailureReportRes);
	   break;
   case  31: /*Count Request*/
	   offset = dissect_ansi_map_CountRequestRes(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_countRequestRes);
	   break;
   case  32: /*Inter System Page*/
	   offset = dissect_ansi_map_InterSystemPageRes(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_interSystemPageRes);
	   break;
   case  33: /*Unsolicited Response*/
	   offset = dissect_ansi_map_UnsolicitedResponseRes(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_unsolicitedResponseRes);
	   break;
   case  35: /*Handoff Measurement Request 2*/
	   offset = dissect_ansi_map_HandoffMeasurementRequest2Res(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_handoffMeasurementRequest2Res);
	   break;
   case  36: /*Facilities Directive 2*/
	   offset = dissect_ansi_map_FacilitiesDirective2Res(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_facilitiesDirective2Res);
	   break;
   case  37: /*Handoff Back 2*/
	   offset = dissect_ansi_map_HandoffBack2Res(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_handoffBack2Res);
	   break;
   case  38: /*Handoff To Third 2*/
	   offset = dissect_ansi_map_HandoffToThird2Res(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_handoffToThird2Res);
	   break;
   case  39: /*Authentication Directive Forward*/
	   offset = dissect_ansi_map_AuthenticationDirectiveForwardRes(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_authenticationDirectiveForwardRes);
	   break;
   case  40: /*Authentication Status Report*/
	   offset = dissect_ansi_map_AuthenticationStatusReportRes(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_authenticationStatusReportRes);
	   break;
			 /*Reserved 41*/
   case  43: /*Information Forward*/
	   offset = dissect_ansi_map_InformationForwardRes(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_informationForwardRes);
	   break;
   case  45: /*Inter System Page 2*/
	   offset = dissect_ansi_map_InterSystemPage2Res(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_interSystemPage2Res);
	   break;
   case  46: /*Inter System Setup*/
	   offset = dissect_ansi_map_InterSystemSetupRes(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_interSystemSetupRes);
	   break;
  case  47: /*OriginationRequest*/
	  offset = dissect_ansi_map_OriginationRequestRes(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_originationRequestRes);
	  break;
  case  48: /*Random Variable Request*/
	  offset = dissect_ansi_map_RandomVariableRequestRes(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_randomVariableRequestRes);
	  break;
  case  50: /*Remote User Interaction Directive*/
	  offset = dissect_ansi_map_RemoteUserInteractionDirectiveRes(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_remoteUserInteractionDirectiveRes);
	  break;
  case  51: /*SMS Delivery Backward*/
	  offset = dissect_ansi_map_SMSDeliveryBackwardRes(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_sMSDeliveryBackwardRes);
	  break;
  case  52: /*SMS Delivery Forward*/
	  offset = dissect_ansi_map_SMSDeliveryForwardRes(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_sMSDeliveryForwardRes);
	  break;
  case  53: /*SMS Delivery Point to Point*/
	  offset = dissect_ansi_map_SMSDeliveryPointToPointRes(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_sMSDeliveryPointToPointRes);
	  break;
  case  54: /*SMS Notification*/
	  offset = dissect_ansi_map_SMSNotificationRes(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_sMSNotificationRes);
	  break;
  case  55: /*SMS Request*/
	  offset = dissect_ansi_map_SMSRequestRes(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_sMSRequestRes);
	  break;
	  /*  N.S0008-0 v 1.0 */
  case  56: /*OTASP Request 6.4.2.CC*/
	  offset = dissect_ansi_map_OTASPRequestRes(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_oTASPRequestRes);
	  break;
  case  58: /*Change Facilities*/
	  offset = dissect_ansi_map_ChangeFacilitiesRes(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_changeFacilitiesRes);
	  break;
  case  59: /*Change Service*/
	  offset = dissect_ansi_map_ChangeServiceRes(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_changeServiceRes);
	  break;
  case  60: /*Parameter Request*/
	  offset = dissect_ansi_map_ParameterRequestRes(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_parameterRequestRes);
	  break;
  case  61: /*TMSI Directive*/
	  offset = dissect_ansi_map_TMSIDirectiveRes(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_tMSIDirectiveRes);
	  break;
  case  63: /*Service Request*/
	  offset = dissect_ansi_map_ServiceRequestRes(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_serviceRequestRes);
	  break;
	  /* N.S0013 */
  case  64: /*Analyzed Information Request*/
	  offset = dissect_ansi_map_AnalyzedInformationRes(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_analyzedInformationRes);
	  break;
  case  68: /*Facility Selected and Available*/
	  offset = dissect_ansi_map_FacilitySelectedAndAvailableRes(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_facilitySelectedAndAvailableRes);
	  break;
  case  70: /*Modify*/
	  offset = dissect_ansi_map_ModifyRes(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_modifyRes);
	  break;
  case  72: /*Search*/
	  offset = dissect_ansi_map_SearchRes(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_searchRes);;
	  break;
  case  73: /*Seize Resource*/
	  offset = dissect_ansi_map_SeizeResourceRes(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_seizeResourceRes);
	  break;
  case  74: /*SRF Directive*/
	  offset = dissect_ansi_map_SRFDirectiveRes(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_sRFDirectiveRes);
	  break;
  case  75: /*T Busy*/
	  offset = dissect_ansi_map_TBusyRes(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_tBusyRes);
	  break;
  case  76: /*T NoAnswer*/
	  offset = dissect_ansi_map_TNoAnswerRes(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_tNoAnswerRes);
	  break;
  case  81: /*Call Control Directive*/
	  offset = dissect_ansi_map_CallControlDirectiveRes(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_callControlDirectiveRes);
	  break;
  case  83: /*O Disconnect*/
	  offset = dissect_ansi_map_ODisconnectRes(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_oDisconnectRes);
	  break;
  case  86: /*T Disconnect*/
	  offset = dissect_ansi_map_TDisconnectRes(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_tDisconnectRes);
	  break;
  case  88: /*O CalledPartyBusy*/
	  offset = dissect_ansi_map_OCalledPartyBusyRes(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_oCalledPartyBusyRes);
	  break;
   case  89: /*O NoAnswer*/
	  offset = dissect_ansi_map_ONoAnswerRes(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_oNoAnswerRes);
	  break;
  case  90: /*Position Request*/
	  offset = dissect_ansi_map_PositionRequestRes(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_positionRequestRes);
	  break;
  case  91: /*Position Request Forward*/
	  offset = dissect_ansi_map_PositionRequestForwardRes(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_positionRequestForwardRes);
	  break;
  case  98: /*Roamer Database Verification Request*/
	  offset = dissect_ansi_map_RoamerDatabaseVerificationRequestRes(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_roamerDatabaseVerificationRequestRes);
	  break;
  case  99: /*Add Service*/
	  offset = dissect_ansi_map_AddServiceRes(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_addServiceRes);
	  break;
  case  100: /*Drop Service*/
	  offset = dissect_ansi_map_DropServiceRes(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_dropServiceRes);
	  break;
	  /*End N.S0029 */

 default:
	  proto_tree_add_text(tree, tvb, offset, -1, "Unknown invokeData blob");
	  break;
  }

  return offset;

 }

static void
dissect_ansi_map(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ansi_map_item;
    proto_tree *ansi_map_tree = NULL;
    int        offset = 0;

	SMS_BearerData_tvb = NULL;
    g_pinfo = pinfo;
	g_tree = tree;
    /*
     * Make entry in the Protocol column on summary display
     */
    if (check_col(pinfo->cinfo, COL_PROTOCOL))
    {
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "ANSI MAP");
    }

	/*
	 * create the ansi_map protocol tree
	 */
	ansi_map_item = proto_tree_add_item(tree, proto_ansi_map, tvb, 0, -1, FALSE);
	ansi_map_tree = proto_item_add_subtree(ansi_map_item, ett_ansi_map);
	ansi_map_is_invoke = FALSE;
	is683_ota = FALSE;
	is801_pld = FALSE;
	dissect_ansi_map_ComponentPDU(FALSE, tvb, offset, pinfo, ansi_map_tree, -1);

}

static void range_delete_callback(guint32 ssn)
 {
	if (ssn) {
		delete_ansi_tcap_subdissector(ssn , ansi_map_handle);
 		add_ansi_tcap_subdissector(ssn , ansi_map_handle);
    }
 }

 static void range_add_callback(guint32 ssn)
 {
	if (ssn) {
		 add_ansi_tcap_subdissector(ssn , ansi_map_handle);
	}
 }

 void
 proto_reg_handoff_ansi_map(void)
 {
     static int ansi_map_prefs_initialized = FALSE;
     data_handle = find_dissector("data");
     
     if(!ansi_map_prefs_initialized)
     {
 	ansi_map_prefs_initialized = TRUE;
 	ansi_map_handle = create_dissector_handle(dissect_ansi_map, proto_ansi_map);
     }
     else
     {
 	range_foreach(ssn_range, range_delete_callback);
     }
     
     g_free(ssn_range);
     ssn_range = range_copy(global_ssn_range);
 
     range_foreach(ssn_range, range_add_callback);
 }

/*--- proto_register_ansi_map -------------------------------------------*/
void proto_register_ansi_map(void) {

  module_t	*ansi_map_module;

  /* List of fields */
    static hf_register_info hf[] = {

    { &hf_ansi_map_op_code_fam,
      { "Operation Code Family", "ansi_map.op_code_fam",
        FT_UINT8, BASE_DEC, NULL, 0,
        "Operation Code Family", HFILL }},
	{ &hf_ansi_map_reservedBitH,
      { "Reserved", "ansi_map.reserved_bitH",
        FT_BOOLEAN, 8, NULL,0x80,
        "Reserved", HFILL }},
	{ &hf_ansi_map_reservedBitD,
      { "Reserved", "ansi_map.reserved_bitH",
        FT_BOOLEAN, 8, NULL,0x08,
        "Reserved", HFILL }},
	{ &hf_ansi_map_reservedBitHG,
      { "Reserved", "ansi_map.reserved_bitHG",
       FT_UINT8, BASE_DEC, NULL, 0x18,
         "Reserved", HFILL }},
	{ &hf_ansi_map_reservedBitED,
      { "Reserved", "ansi_map.reserved_bitED",
       FT_UINT8, BASE_DEC, NULL, 0x18,
         "Reserved", HFILL }},
    { &hf_ansi_map_op_code,
      { "Operation Code", "ansi_map.op_code",
        FT_UINT8, BASE_DEC, VALS(ansi_map_opr_code_strings), 0x0,
        "Operation Code", HFILL }},
	{ &hf_ansi_map_type_of_digits,
      { "Type of Digits", "ansi_map.type_of_digits",
        FT_UINT8, BASE_DEC, VALS(ansi_map_type_of_digits_vals), 0x0,
        "Type of Digits", HFILL }},
	{ &hf_ansi_map_na,
      { "Nature of Number", "ansi_map.na",
        FT_BOOLEAN, 8, TFS(&ansi_map_na_bool_val),0x01,
        "Nature of Number", HFILL }},
	{ &hf_ansi_map_pi,
      { "Presentation Indication", "ansi_map.type_of_pi",
        FT_BOOLEAN, 8, TFS(&ansi_map_pi_bool_val),0x02,
        "Presentation Indication", HFILL }},
	{ &hf_ansi_map_navail,
      { "Numer available indication", "ansi_map.navail",
        FT_BOOLEAN, 8, TFS(&ansi_map_navail_bool_val),0x04,
        "Numer available indication", HFILL }},
	{ &hf_ansi_map_si,
      { "Screening indication", "ansi_map.si",
        FT_UINT8, BASE_DEC, VALS(ansi_map_si_vals), 0x30,
        "Screening indication", HFILL }},
	{ &hf_ansi_map_digits_enc,
      { "Encoding", "ansi_map.enc",
        FT_UINT8, BASE_DEC, VALS(ansi_map_digits_enc_vals), 0x0f,
        "Encoding", HFILL }},
	{ &hf_ansi_map_np,
      { "Numbering Plan", "ansi_map.np",
        FT_UINT8, BASE_DEC, VALS(ansi_map_np_vals), 0xf0,
        "Numbering Plan", HFILL }},
	{ &hf_ansi_map_nr_digits,
      { "Number of Digits", "ansi_map.nr_digits",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "Number of Digits", HFILL }},
	{ &hf_ansi_map_bcd_digits,
      { "BCD digits", "gsm_map.bcd_digits",
        FT_STRING, BASE_NONE, NULL, 0,
        "BCD digits", HFILL }},
	{ &hf_ansi_map_ia5_digits,
      { "IA5 digits", "gsm_map.ia5_digits",
        FT_STRING, BASE_NONE, NULL, 0,
        "IA5 digits", HFILL }},
	{ &hf_ansi_map_subaddr_type,
      { "Type of Subaddress", "ansi_subaddr_type",
        FT_UINT8, BASE_DEC, VALS(ansi_map_sub_addr_type_vals), 0x70,
        "Type of Subaddress", HFILL }},
	{ &hf_ansi_map_subaddr_odd_even,
      { "Odd/Even Indicator", "ansi_map.subaddr_odd_even",
        FT_BOOLEAN, 8, TFS(&ansi_map_navail_bool_val),0x08,
        "Odd/Even Indicator", HFILL }},

	{ &hf_ansi_alertcode_cadence,
      { "Cadence", "ansi_map._alertcode.cadence",
        FT_UINT8, BASE_DEC, VALS(ansi_map_AlertCode_Cadence_vals), 0x3f,
        "Cadence", HFILL }},
	{ &hf_ansi_alertcode_pitch,
      { "Pitch", "ansi_map._alertcode.pitch",
        FT_UINT8, BASE_DEC, VALS(ansi_map_AlertCode_Pitch_vals), 0xc0,
        "Pitch", HFILL }},
	{ &hf_ansi_alertcode_alertaction,
      { "Alert Action", "ansi_map._alertcode.alertaction",
        FT_UINT8, BASE_DEC, VALS(ansi_map_AlertCode_Alert_Action_vals), 0x07,
        "Alert Action", HFILL }},
    { &hf_ansi_map_announcementcode_tone,
      { "Tone", "ansi_map.announcementcode.tone",
        FT_UINT8, BASE_DEC, VALS(ansi_map_AnnouncementCode_tone_vals), 0x0,
        "Tone", HFILL }},
    { &hf_ansi_map_announcementcode_class,
      { "Tone", "ansi_map.announcementcode.class",
        FT_UINT8, BASE_DEC, VALS(ansi_map_AnnouncementCode_class_vals), 0xf,
        "Tone", HFILL }},
    { &hf_ansi_map_announcementcode_std_ann,
      { "Standard Announcement", "ansi_map.announcementcode.std_ann",
        FT_UINT8, BASE_DEC, VALS(ansi_map_AnnouncementCode_std_ann_vals), 0x0,
        "Standard Announcement", HFILL }},
    { &hf_ansi_map_announcementcode_cust_ann,
      { "Custom Announcement", "ansi_map.announcementcode.cust_ann",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "Custom Announcement", HFILL }},
	{ &hf_ansi_map_authorizationperiod_period,
      { "Period", "ansi_map.authorizationperiod.period",
        FT_UINT8, BASE_DEC, VALS(ansi_map_authorizationperiod_period_vals), 0x0,
        "Period", HFILL }},
	{ &hf_ansi_map_value,
      { " Value", "ansi_map.value",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "Value", HFILL }},
	{ &hf_ansi_map_msc_type,
      { "Type", "ansi_map.extendedmscid.type",
        FT_UINT8, BASE_DEC, VALS(ansi_map_msc_type_vals), 0x0,
        "Type", HFILL }},
	{ &hf_ansi_map_handoffstate_pi,
      { "Party Involved (PI)", "ansi_map.handoffstate.pi",
        FT_BOOLEAN, 8, TFS(&ansi_map_HandoffState_pi_bool_val),0x01,
        "Party Involved (PI)", HFILL }},
	{ &hf_ansi_map_tgn,
      { "Trunk Group Number (G)", "ansi_map.tgn",
        FT_UINT8, BASE_DEC, NULL,0x0,
        "Trunk Group Number (G)", HFILL }},
	{ &hf_ansi_map_tmn,
      { "Trunk Member Number (M)", "ansi_map.tgn",
        FT_UINT8, BASE_DEC, NULL,0x0,
        "Trunk Member Number (M)", HFILL }},
	{ &hf_ansi_map_messagewaitingnotificationcount_tom,
      { "Type of messages", "ansi_map.messagewaitingnotificationcount.tom",
        FT_UINT8, BASE_DEC, VALS(ansi_map_MessageWaitingNotificationCount_type_vals), 0x0,
        "Type of messages", HFILL }},
	{ &hf_ansi_map_messagewaitingnotificationcount_no_mw,
      { "Number of Messages Waiting", "ansi_map.messagewaitingnotificationcount.nomw",
        FT_UINT8, BASE_DEC, NULL,0x0,
        "Number of Messages Waiting", HFILL }},
	{ &hf_ansi_map_messagewaitingnotificationtype_mwi,
      { "Message Waiting Indication (MWI)", "ansi_map.messagewaitingnotificationcount.mwi",
        FT_UINT8, BASE_DEC, VALS(ansi_map_MessageWaitingNotificationType_mwi_vals), 0x0,
        "Message Waiting Indication (MWI)", HFILL }},
	{ &hf_ansi_map_messagewaitingnotificationtype_apt,
      { "Alert Pip Tone (APT)", "ansi_map.messagewaitingnotificationtype.apt",
        FT_BOOLEAN, 8, TFS(&ansi_map_HandoffState_pi_bool_val),0x02,
        "Alert Pip Tone (APT)", HFILL }},
	{ &hf_ansi_map_messagewaitingnotificationtype_pt,
      { "Pip Tone (PT)", "ansi_map.messagewaitingnotificationtype.pt",
        FT_UINT8, BASE_DEC, VALS(ansi_map_MessageWaitingNotificationType_mwi_vals), 0xc0,
        "Pip Tone (PT)", HFILL }},

	{ &hf_ansi_map_trans_cap_prof,
      { "Profile (PROF)", "ansi_map.trans_cap_prof",
        FT_BOOLEAN, 8, TFS(&ansi_map_trans_cap_prof_bool_val),0x01,
        "Profile (PROF)", HFILL }},
	{ &hf_ansi_map_trans_cap_busy,
      { "Busy Detection (BUSY)", "ansi_map.trans_cap_busy",
        FT_BOOLEAN, 8, TFS(&ansi_map_trans_cap_busy_bool_val),0x02,
        "Busy Detection (BUSY)", HFILL }},
	{ &hf_ansi_map_trans_cap_ann,
      { "Announcements (ANN)", "ansi_map.trans_cap_ann",
        FT_BOOLEAN, 8, TFS(&ansi_map_trans_cap_ann_bool_val),0x04,
        "Announcements (ANN)", HFILL }},
	{ &hf_ansi_map_trans_cap_rui,
      { "Remote User Interaction (RUI)", "ansi_map.trans_cap_rui",
        FT_BOOLEAN, 8, TFS(&ansi_map_trans_cap_rui_bool_val),0x08,
        "Remote User Interaction (RUI)", HFILL }},
	{ &hf_ansi_map_trans_cap_spini,
      { "Subscriber PIN Intercept (SPINI)", "ansi_map.trans_cap_spini",
        FT_BOOLEAN, 8, TFS(&ansi_map_trans_cap_spini_bool_val),0x10,
        "Subscriber PIN Intercept (SPINI)", HFILL }},
	{ &hf_ansi_map_trans_cap_uzci,
      { "UZ Capability Indicator (UZCI)", "ansi_map.trans_cap_uzci",
        FT_BOOLEAN, 8, TFS(&ansi_map_trans_cap_uzci_bool_val),0x20,
        "UZ Capability Indicator (UZCI)", HFILL }},
	{ &hf_ansi_map_trans_cap_ndss,
      { "NDSS Capability (NDSS)", "ansi_map.trans_cap_ndss",
        FT_BOOLEAN, 8, TFS(&ansi_map_trans_cap_ndss_bool_val),0x40,
        "NDSS Capability (NDSS)", HFILL }},		
	{ &hf_ansi_map_trans_cap_nami,
      { "NAME Capability Indicator (NAMI)", "ansi_map.trans_cap_nami",
        FT_BOOLEAN, 8, TFS(&ansi_map_trans_cap_nami_bool_val),0x80,
        "NAME Capability Indicator (NAMI)", HFILL }},
	{ &hf_ansi_trans_cap_multerm,
      { "Multiple Terminations", "ansi_map.trans_cap_multerm",
        FT_UINT8, BASE_DEC, VALS(ansi_map_trans_cap_multerm_vals), 0x0f,
        "Multiple Terminations", HFILL }},
    { &hf_ansi_map_terminationtriggers_busy,
      { "Busy", "ansi_map.terminationtriggers.busy",
        FT_UINT8, BASE_DEC, VALS(ansi_map_terminationtriggers_busy_vals), 0x03,
        "Busy", HFILL }},
    { &hf_ansi_map_terminationtriggers_rf,
      { "Routing Failure (RF)", "ansi_map.terminationtriggers.rf",
        FT_UINT8, BASE_DEC, VALS(ansi_map_terminationtriggers_rf_vals), 0x0c,
        "Routing Failure (RF)", HFILL }},
    { &hf_ansi_map_terminationtriggers_npr,
      { "No Page Response (NPR)", "ansi_map.terminationtriggers.npr",
        FT_UINT8, BASE_DEC, VALS(ansi_map_terminationtriggers_npr_vals), 0x30,
        "No Page Response (NPR)", HFILL }},
    { &hf_ansi_map_terminationtriggers_na,
      { "No Answer (NA)", "ansi_map.terminationtriggers.na",
        FT_UINT8, BASE_DEC, VALS(ansi_map_terminationtriggers_na_vals), 0xc0,
        "No Answer (NA)", HFILL }},
    { &hf_ansi_map_terminationtriggers_nr,
      { "None Reachable (NR)", "ansi_map.terminationtriggers.nr",
        FT_UINT8, BASE_DEC, VALS(ansi_map_terminationtriggers_nr_vals), 0x01,
        "None Reachable (NR)", HFILL }},
	{ &hf_ansi_trans_cap_tl,
      { "TerminationList (TL)", "ansi_map.trans_cap_tl",
        FT_BOOLEAN, 8, TFS(&ansi_map_trans_cap_tl_bool_val),0x10,
        "TerminationList (TL)", HFILL }},
	{ &hf_ansi_map_cdmaserviceoption,
      { "CDMAServiceOption", "ansi_map.cdmaserviceoption",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "CDMAServiceOption", HFILL }},
	{ &hf_ansi_trans_cap_waddr,
      { "WIN Addressing (WADDR)", "ansi_map.trans_cap_waddr",
        FT_BOOLEAN, 8, TFS(&ansi_map_trans_cap_waddr_bool_val),0x20,
        "WIN Addressing (WADDR)", HFILL }},

	{ &hf_ansi_map_MarketID,
      { "MarketID", "ansi_map.marketid",
        FT_UINT16, BASE_DEC, NULL, 0,
        "MarketID", HFILL }},
	{ &hf_ansi_map_swno,
      { "Switch Number (SWNO)", "ansi_map.swno",
        FT_UINT8, BASE_DEC, NULL, 0,
        "Switch Number (SWNO)", HFILL }},
	{ &hf_ansi_map_idno,
      { "ID Number", "ansi_map.idno",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ID Number", HFILL }},
	{ &hf_ansi_map_segcount,
      { "Segment Counter", "ansi_map.segcount",
        FT_UINT8, BASE_DEC, NULL, 0,
        "Segment Counter", HFILL }},
	{ &hf_ansi_map_systemcapabilities_auth,
      { "Authentication Parameters Requested (AUTH)", "ansi_map.systemcapabilities.auth",
        FT_BOOLEAN, 8, TFS(&ansi_map_systemcapabilities_auth_bool_val),0x01,
        "Authentication Parameters Requested (AUTH)", HFILL }},
	{ &hf_ansi_map_systemcapabilities_se,
      { "Signaling Message Encryption Capable (SE )", "ansi_map.systemcapabilities.se",
        FT_BOOLEAN, 8, TFS(&ansi_map_systemcapabilities_se_bool_val),0x02,
        "Signaling Message Encryption Capable (SE )", HFILL }},
	{ &hf_ansi_map_systemcapabilities_vp,
      { "Voice Privacy Capable (VP )", "ansi_map.systemcapabilities.vp",
        FT_BOOLEAN, 8, TFS(&ansi_map_systemcapabilities_vp_bool_val),0x04,
        "Voice Privacy Capable (VP )", HFILL }},
	{ &hf_ansi_map_systemcapabilities_cave,
      { "CAVE Algorithm Capable (CAVE)", "ansi_map.systemcapabilities.cave",
        FT_BOOLEAN, 8, TFS(&ansi_map_systemcapabilities_cave_bool_val),0x08,
        "CAVE Algorithm Capable (CAVE)", HFILL }},
	{ &hf_ansi_map_systemcapabilities_ssd,
      { "Shared SSD (SSD)", "ansi_map.systemcapabilities.ssd",
        FT_BOOLEAN, 8, TFS(&ansi_map_systemcapabilities_ssd_bool_val),0x10,
        "Shared SSD (SSD)", HFILL }},
	{ &hf_ansi_map_systemcapabilities_dp,
      { "Data Privacy (DP)", "ansi_map.systemcapabilities.dp",
        FT_BOOLEAN, 8, TFS(&ansi_map_systemcapabilities_dp_bool_val),0x20,
        "Data Privacy (DP)", HFILL }},

	{ &hf_ansi_map_mslocation_lat,
      { "Latitude in tenths of a second", "ansi_map.mslocation.lat",
        FT_UINT8, BASE_DEC, NULL, 0,
        "Latitude in tenths of a second", HFILL }},
	{ &hf_ansi_map_mslocation_long,
      { "Longitude in tenths of a second", "ansi_map.mslocation.long",
        FT_UINT8, BASE_DEC, NULL, 0,
        "Switch Number (SWNO)", HFILL }},
	{ &hf_ansi_map_mslocation_res,
      { "Resolution in units of 1 foot", "ansi_map.mslocation.res",
        FT_UINT8, BASE_DEC, NULL, 0,
        "Resolution in units of 1 foot", HFILL }},
	{ &hf_ansi_map_nampscallmode_namps,
      { "Call Mode", "ansi_map.nampscallmode.namps",
        FT_BOOLEAN, 8, TFS(&ansi_map_CallMode_namps_bool_val),0x01,
        "Call Mode", HFILL }},
	{ &hf_ansi_map_nampscallmode_amps,
      { "Call Mode", "ansi_map.nampscallmode.amps",
        FT_BOOLEAN, 8, TFS(&ansi_map_CallMode_amps_bool_val),0x02,
        "Call Mode", HFILL }},
	{ &hf_ansi_map_nampschanneldata_navca,
      { "Narrow Analog Voice Channel Assignment (NAVCA)", "ansi_map.nampschanneldata.navca",
        FT_UINT8, BASE_DEC, VALS(ansi_map_NAMPSChannelData_navca_vals), 0x03,
        "Narrow Analog Voice Channel Assignment (NAVCA)", HFILL }},
	{ &hf_ansi_map_nampschanneldata_CCIndicator,
      { "Color Code Indicator (CCIndicator)", "ansi_map.nampschanneldata.ccindicator",
        FT_UINT8, BASE_DEC, VALS(ansi_map_NAMPSChannelData_ccinidicator_vals), 0x1c,
        "Color Code Indicator (CCIndicator)", HFILL }},


	{ &hf_ansi_map_callingfeaturesindicator_cfufa,
      { "Call Forwarding Unconditional FeatureActivity, CFU-FA", "ansi_map.callingfeaturesindicator.cfufa",
        FT_UINT8, BASE_DEC, VALS(ansi_map_FeatureActivity_vals), 0x03,
        "Call Forwarding Unconditional FeatureActivity, CFU-FA", HFILL }},
	{ &hf_ansi_map_callingfeaturesindicator_cfbfa,
      { "Call Forwarding Busy FeatureActivity, CFB-FA", "ansi_map.callingfeaturesindicator.cfbafa",
        FT_UINT8, BASE_DEC, VALS(ansi_map_FeatureActivity_vals), 0x0c,
        "Call Forwarding Busy FeatureActivity, CFB-FA", HFILL }},
	{ &hf_ansi_map_callingfeaturesindicator_cfnafa,
      { "Call Forwarding No Answer FeatureActivity, CFNA-FA", "ansi_map.callingfeaturesindicator.cfnafa",
        FT_UINT8, BASE_DEC, VALS(ansi_map_FeatureActivity_vals), 0x30,
        "Call Forwarding No Answer FeatureActivity, CFNA-FA", HFILL }},
	{ &hf_ansi_map_callingfeaturesindicator_cwfa,
      { "Call Waiting: FeatureActivity, CW-FA", "ansi_map.callingfeaturesindicator.cwfa",
        FT_UINT8, BASE_DEC, VALS(ansi_map_FeatureActivity_vals), 0xc0,
        "Call Waiting: FeatureActivity, CW-FA", HFILL }},

	{ &hf_ansi_map_callingfeaturesindicator_3wcfa,
      { "Three-Way Calling FeatureActivity, 3WC-FA", "ansi_map.callingfeaturesindicator.3wcfa",
        FT_UINT8, BASE_DEC, VALS(ansi_map_FeatureActivity_vals), 0x03,
        "Three-Way Calling FeatureActivity, 3WC-FA", HFILL }},

	{ &hf_ansi_map_callingfeaturesindicator_pcwfa,
      { "Priority Call Waiting FeatureActivity PCW-FA", "ansi_map.callingfeaturesindicator.pcwfa",
        FT_UINT8, BASE_DEC, VALS(ansi_map_FeatureActivity_vals), 0x03,
        "Priority Call Waiting FeatureActivity PCW-FA", HFILL }},
	  
	{ &hf_ansi_map_callingfeaturesindicator_dpfa,
      { "Data Privacy Feature Activity DP-FA", "ansi_map.callingfeaturesindicator.dpfa",
        FT_UINT8, BASE_DEC, VALS(ansi_map_FeatureActivity_vals), 0x0c,
        "Data Privacy Feature Activity DP-FA", HFILL }},
	{ &hf_ansi_map_callingfeaturesindicator_ahfa,
      { "Answer Hold: FeatureActivity AH-FA", "ansi_map.callingfeaturesindicator.ahfa",
        FT_UINT8, BASE_DEC, VALS(ansi_map_FeatureActivity_vals), 0x30,
        "Answer Hold: FeatureActivity AH-FA", HFILL }},
	{ &hf_ansi_map_callingfeaturesindicator_uscfvmfa,
      { "USCF divert to voice mail: FeatureActivity USCFvm-FA", "ansi_map.callingfeaturesindicator.uscfvmfa",
        FT_UINT8, BASE_DEC, VALS(ansi_map_FeatureActivity_vals), 0xc0,
        "USCF divert to voice mail: FeatureActivity USCFvm-FA", HFILL }},

	{ &hf_ansi_map_callingfeaturesindicator_uscfmsfa,
      { "USCF divert to mobile station provided DN:FeatureActivity.USCFms-FA", "ansi_map.callingfeaturesindicator.uscfmsfa",
        FT_UINT8, BASE_DEC, VALS(ansi_map_FeatureActivity_vals), 0x03,
        "USCF divert to mobile station provided DN:FeatureActivity.USCFms-FA", HFILL }},
	{ &hf_ansi_map_callingfeaturesindicator_uscfnrfa,
      { "USCF divert to network registered DN:FeatureActivity. USCFnr-FA", "ansi_map.callingfeaturesindicator.uscfmsfa",
        FT_UINT8, BASE_DEC, VALS(ansi_map_FeatureActivity_vals), 0x0c,
        "USCF divert to network registered DN:FeatureActivity. USCFnr-FA", HFILL }},
	{ &hf_ansi_map_callingfeaturesindicator_cpdsfa,
      { "CDMA-Packet Data Service: FeatureActivity. CPDS-FA", "ansi_map.callingfeaturesindicator.cpdfa",
        FT_UINT8, BASE_DEC, VALS(ansi_map_FeatureActivity_vals), 0x30,
        "CDMA-Packet Data Service: FeatureActivity. CPDS-FA", HFILL }},
	{ &hf_ansi_map_callingfeaturesindicator_ccsfa,
      { "CDMA-Concurrent Service:FeatureActivity. CCS-FA", "ansi_map.callingfeaturesindicator.ccsfa",
        FT_UINT8, BASE_DEC, VALS(ansi_map_FeatureActivity_vals), 0xc0,
        "CDMA-Concurrent Service:FeatureActivity. CCS-FA", HFILL }},

	{ &hf_ansi_map_callingfeaturesindicator_epefa,
      { "TDMA Enhanced Privacy and Encryption:FeatureActivity.TDMA EPE-FA", "ansi_map.callingfeaturesindicator.epefa",
        FT_UINT8, BASE_DEC, VALS(ansi_map_FeatureActivity_vals), 0x03,
        "TDMA Enhanced Privacy and Encryption:FeatureActivity.TDMA EPE-FA", HFILL }},


	{ &hf_ansi_map_callingfeaturesindicator_cdfa,
      { "Call Delivery: FeatureActivity, CD-FA", "ansi_map.callingfeaturesindicator.cdfa",
        FT_UINT8, BASE_DEC, VALS(ansi_map_FeatureActivity_vals), 0x0c,
        "Call Delivery: FeatureActivity, CD-FA", HFILL }},
	{ &hf_ansi_map_callingfeaturesindicator_vpfa,
      { "Voice Privacy FeatureActivity, VP-FA", "ansi_map.callingfeaturesindicator.vpfa",
        FT_UINT8, BASE_DEC, VALS(ansi_map_FeatureActivity_vals), 0x30,
        "Voice Privacy FeatureActivity, VP-FA", HFILL }},
	{ &hf_ansi_map_callingfeaturesindicator_ctfa,
      { "Call Transfer: FeatureActivity, CT-FA", "ansi_map.callingfeaturesindicator.ctfa",
        FT_UINT8, BASE_DEC, VALS(ansi_map_FeatureActivity_vals), 0xc0,
        "Call Transfer: FeatureActivity, CT-FA", HFILL }},

	{ &hf_ansi_map_callingfeaturesindicator_cnip1fa,
      { "One number (network-provided only) Calling Number Identification Presentation: FeatureActivity CNIP1-FA", "ansi_map.callingfeaturesindicator.cnip1fa",
        FT_UINT8, BASE_DEC, VALS(ansi_map_FeatureActivity_vals), 0x03,
        "One number (network-provided only) Calling Number Identification Presentation: FeatureActivity CNIP1-FA", HFILL }},
	{ &hf_ansi_map_callingfeaturesindicator_cnip2fa,
      { "Two number (network-provided and user-provided) Calling Number Identification Presentation: FeatureActivity CNIP2-FA", "ansi_map.callingfeaturesindicator.cnip2fa",
        FT_UINT8, BASE_DEC, VALS(ansi_map_FeatureActivity_vals), 0x0c,
        "Two number (network-provided and user-provided) Calling Number Identification Presentation: FeatureActivity CNIP2-FA", HFILL }},
	{ &hf_ansi_map_callingfeaturesindicator_cnirfa,
      { "Calling Number Identification Restriction: FeatureActivity CNIR-FA", "ansi_map.callingfeaturesindicator.cnirfa",
        FT_UINT8, BASE_DEC, VALS(ansi_map_FeatureActivity_vals), 0x30,
        "Calling Number Identification Restriction: FeatureActivity CNIR-FA", HFILL }},
	{ &hf_ansi_map_callingfeaturesindicator_cniroverfa,
      { "Calling Number Identification Restriction Override FeatureActivity CNIROver-FA", "ansi_map.callingfeaturesindicator.cniroverfa",
        FT_UINT8, BASE_DEC, VALS(ansi_map_FeatureActivity_vals), 0xc0,
        "", HFILL }},

	{ &hf_ansi_map_cdmacallmode_cdma,
      { "Call Mode", "ansi_map.cdmacallmode.cdma",
        FT_BOOLEAN, 8, TFS(&ansi_map_CDMACallMode_cdma_bool_val),0x01,
        "Call Mode", HFILL }},
	{ &hf_ansi_map_cdmacallmode_amps,
      { "Call Mode", "ansi_map.ocdmacallmode.amps",
        FT_BOOLEAN, 8, TFS(&ansi_map_CallMode_amps_bool_val),0x02,
        "Call Mode", HFILL }},
	{ &hf_ansi_map_cdmacallmode_namps,
      { "Call Mode", "ansi_map.cdmacallmode.namps",
        FT_BOOLEAN, 8, TFS(&ansi_map_CallMode_namps_bool_val),0x04,
        "Call Mode", HFILL }},
	{ &hf_ansi_map_cdmacallmode_cls1,
      { "Call Mode", "ansi_map.cdmacallmode.cls1",
        FT_BOOLEAN, 8, TFS(&ansi_map_CDMACallMode_cls1_bool_val),0x08,
        "Call Mode", HFILL }},
	{ &hf_ansi_map_cdmacallmode_cls2,
      { "Call Mode", "ansi_map.cdmacallmode.cls2",
        FT_BOOLEAN, 8, TFS(&ansi_map_CDMACallMode_cls2_bool_val),0x10,
        "Call Mode", HFILL }},
	{ &hf_ansi_map_cdmacallmode_cls3,
      { "Call Mode", "ansi_map.cdmacallmode.cls3",
        FT_BOOLEAN, 8, TFS(&ansi_map_CDMACallMode_cls3_bool_val),0x20,
        "Call Mode", HFILL }},
	{ &hf_ansi_map_cdmacallmode_cls4,
      { "Call Mode", "ansi_map.cdmacallmode.cls4",
        FT_BOOLEAN, 8, TFS(&ansi_map_CDMACallMode_cls4_bool_val),0x40,
        "Call Mode", HFILL }},
	{ &hf_ansi_map_cdmacallmode_cls5,
      { "Call Mode", "ansi_map.cdmacallmode.cls5",
        FT_BOOLEAN, 8, TFS(&ansi_map_CDMACallMode_cls5_bool_val),0x80,
        "Call Mode", HFILL }},
	{ &hf_ansi_map_cdmacallmode_cls6,
      { "Call Mode", "ansi_map.cdmacallmode.cls6",
        FT_BOOLEAN, 8, TFS(&ansi_map_CDMACallMode_cls6_bool_val),0x01,
        "Call Mode", HFILL }},
	{ &hf_ansi_map_cdmacallmode_cls7,
      { "Call Mode", "ansi_map.cdmacallmode.cls7",
        FT_BOOLEAN, 8, TFS(&ansi_map_CDMACallMode_cls7_bool_val),0x02,
        "Call Mode", HFILL }},
	{ &hf_ansi_map_cdmacallmode_cls8,
      { "Call Mode", "ansi_map.cdmacallmode.cls8",
        FT_BOOLEAN, 8, TFS(&ansi_map_CDMACallMode_cls8_bool_val),0x04,
        "Call Mode", HFILL }},
	{ &hf_ansi_map_cdmacallmode_cls9,
      { "Call Mode", "ansi_map.cdmacallmode.cls9",
        FT_BOOLEAN, 8, TFS(&ansi_map_CDMACallMode_cls9_bool_val),0x08,
        "Call Mode", HFILL }},
	{ &hf_ansi_map_cdmacallmode_cls10,
      { "Call Mode", "ansi_map.cdmacallmode.cls10",
        FT_BOOLEAN, 8, TFS(&ansi_map_CDMACallMode_cls10_bool_val),0x10,
        "Call Mode", HFILL }},
	{&hf_ansi_map_cdmachanneldata_Frame_Offset,
      { "Frame Offset", "ansi_map.cdmachanneldata.frameoffset",
        FT_UINT8, BASE_DEC, NULL, 0x78,
        "Frame Offset", HFILL }},
	{&hf_ansi_map_cdmachanneldata_CDMA_ch_no,
      { "CDMA Channel Number", "ansi_map.cdmachanneldata.cdma_ch_no",
        FT_UINT16, BASE_DEC, NULL, 0x07FF,
        "CDMA Channel Number", HFILL }},
	{&hf_ansi_map_cdmachanneldata_band_cls,
      { "Band Class", "ansi_map.cdmachanneldata.band_cls",
        FT_UINT8, BASE_DEC, VALS(ansi_map_cdmachanneldata_band_cls_vals), 0x7c,
        "Band Class", HFILL }},
	{&hf_ansi_map_cdmachanneldata_lc_mask_b6,
      { "Long Code Mask (byte 6) MSB", "ansi_map.cdmachanneldata.lc_mask_b6",
        FT_UINT8, BASE_HEX, NULL, 0x03,
        "Long Code Mask MSB (byte 6)", HFILL }},
	{&hf_ansi_map_cdmachanneldata_lc_mask_b5,
      { "Long Code Mask (byte 5)", "ansi_map.cdmachanneldata.lc_mask_b5",
        FT_UINT8, BASE_HEX, NULL, 0xff,
        "Long Code Mask (byte 5)", HFILL }},
	{&hf_ansi_map_cdmachanneldata_lc_mask_b4,
      { "Long Code Mask (byte 4)", "ansi_map.cdmachanneldata.lc_mask_b4",
        FT_UINT8, BASE_HEX, NULL, 0xff,
        "Long Code Mask (byte 4)", HFILL }},
	{&hf_ansi_map_cdmachanneldata_lc_mask_b3,
      { "Long Code Mask (byte 3)", "ansi_map.cdmachanneldata.lc_mask_b3",
        FT_UINT8, BASE_HEX, NULL, 0xff,
        "Long Code Mask (byte 3)", HFILL }},
	{&hf_ansi_map_cdmachanneldata_lc_mask_b2,
      { "Long Code Mask (byte 2)", "ansi_map.cdmachanneldata.lc_mask_b2",
        FT_UINT8, BASE_HEX, NULL, 0xff,
        "Long Code Mask (byte 2)", HFILL }},
	{&hf_ansi_map_cdmachanneldata_lc_mask_b1,
      { "Long Code Mask LSB(byte 1)", "ansi_map.cdmachanneldata.lc_mask_b1",
        FT_UINT8, BASE_HEX, NULL, 0xff,
        "Long Code Mask (byte 1)LSB", HFILL }},
	{&hf_ansi_map_cdmachanneldata_np_ext,
      { "NP EXT", "ansi_map.cdmachanneldata.np_ext",
        FT_BOOLEAN, 8, NULL,0x80,
        "NP EXT", HFILL }},
	{&hf_ansi_map_cdmachanneldata_nominal_pwr,
      { "Nominal Power", "ansi_map.cdmachanneldata.nominal_pwr",
        FT_UINT8, BASE_DEC, NULL, 0x71,
        "Nominal Power", HFILL }},
	{&hf_ansi_map_cdmachanneldata_nr_preamble,
      { "Number Preamble", "ansi_map.cdmachanneldata.nr_preamble",
        FT_UINT8, BASE_DEC, NULL, 0x07,
        "Number Preamble", HFILL }},

	{ &hf_ansi_map_cdmastationclassmark_pc,
      { "Power Class(PC)", "ansi_map.cdmastationclassmark.pc",
        FT_UINT8, BASE_DEC, VALS(ansi_map_CDMAStationClassMark_pc_vals), 0x03,
        "Power Class(PC)", HFILL }},

	{ &hf_ansi_map_cdmastationclassmark_dtx,
      { "Analog Transmission: (DTX)", "ansi_map.cdmastationclassmark.dtx",
        FT_BOOLEAN, 8, TFS(&ansi_map_CDMAStationClassMark_dtx_bool_val),0x04,
        "Analog Transmission: (DTX)", HFILL }},
	{ &hf_ansi_map_cdmastationclassmark_smi,
      { " Slotted Mode Indicator: (SMI)", "ansi_map.cdmastationclassmark.smi",
        FT_BOOLEAN, 8, TFS(&ansi_map_CDMAStationClassMark_smi_bool_val),0x20,
        " Slotted Mode Indicator: (SMI)", HFILL }},
	{ &hf_ansi_map_cdmastationclassmark_dmi,
      { "Dual-mode Indicator(DMI)", "ansi_map.cdmastationclassmark.dmi",
        FT_BOOLEAN, 8, TFS(&ansi_map_CDMAStationClassMark_dmi_bool_val),0x40,
        "Dual-mode Indicator(DMI)", HFILL }},
	{ &hf_ansi_map_channeldata_vmac,
      { "Voice Mobile Attenuation Code (VMAC)", "ansi_map.channeldata.vmac",
        FT_UINT8, BASE_DEC, NULL, 0x07,
        "Voice Mobile Attenuation Code (VMAC)", HFILL }},
	{ &hf_ansi_map_channeldata_dtx,
      { "Discontinuous Transmission Mode (DTX)", "ansi_map.channeldata.dtx",
        FT_UINT8, BASE_DEC, VALS(ansi_map_ChannelData_dtx_vals), 0x18,
        "Discontinuous Transmission Mode (DTX)", HFILL }},
	{ &hf_ansi_map_channeldata_scc,
      { "SAT Color Code (SCC)", "ansi_map.channeldata.scc",
        FT_UINT8, BASE_DEC, NULL, 0xc0,
        "SAT Color Code (SCC)", HFILL }},
	{ &hf_ansi_map_channeldata_chno,
      { "Channel Number (CHNO)", "ansi_map.channeldata.chno",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "Channel Number (CHNO)", HFILL }},
	{ &hf_ansi_map_ConfidentialityModes_vp,
      { "Voice Privacy (VP) Confidentiality Status", "ansi_map.confidentialitymodes.vp",
        FT_BOOLEAN, 8, TFS(&ansi_map_ConfidentialityModes_bool_val),0x01,
        "Voice Privacy (VP) Confidentiality Status", HFILL }},
	{ &hf_ansi_map_ConfidentialityModes_se,
      { "Signaling Message Encryption (SE) Confidentiality Status", "ansi_map.confidentialitymodes.se",
        FT_BOOLEAN, 8, TFS(&ansi_map_ConfidentialityModes_bool_val),0x02,
        "Signaling Message Encryption (SE) Confidentiality Status", HFILL }},
	{ &hf_ansi_map_ConfidentialityModes_dp,
      { "DataPrivacy (DP) Confidentiality Status", "ansi_map.confidentialitymodes.dp",
        FT_BOOLEAN, 8, TFS(&ansi_map_ConfidentialityModes_bool_val),0x04,
        "DataPrivacy (DP) Confidentiality Status", HFILL }},

	{ &hf_ansi_map_deniedauthorizationperiod_period,
      { "Period", "ansi_map.deniedauthorizationperiod.period",
        FT_UINT8, BASE_DEC, VALS(ansi_map_deniedauthorizationperiod_period_vals), 0x0,
        "Period", HFILL }},


	{ &hf_ansi_map_originationtriggers_all,
      { "All Origination (All)", "ansi_map.originationtriggers.all",
        FT_BOOLEAN, 8, TFS(&ansi_map_originationtriggers_all_bool_val),0x01,
        "All Origination (All)", HFILL }},
	{ &hf_ansi_map_originationtriggers_local,
      { "Local", "ansi_map.originationtriggers.all",
        FT_BOOLEAN, 8, TFS(&ansi_map_originationtriggers_local_bool_val),0x02,
        "Local", HFILL }},
	{ &hf_ansi_map_originationtriggers_ilata,
      { "Intra-LATA Toll (ILATA)", "ansi_map.originationtriggers.ilata",
        FT_BOOLEAN, 8, TFS(&ansi_map_originationtriggers_ilata_bool_val),0x04,
        "Intra-LATA Toll (ILATA)", HFILL }},
	{ &hf_ansi_map_originationtriggers_olata,
      { "Inter-LATA Toll (OLATA)", "ansi_map.originationtriggers.olata",
        FT_BOOLEAN, 8, TFS(&ansi_map_originationtriggers_olata_bool_val),0x08,
        "Inter-LATA Toll (OLATA)", HFILL }},
	{ &hf_ansi_map_originationtriggers_int,
      { "International (Int'l )", "ansi_map.originationtriggers.int",
        FT_BOOLEAN, 8, TFS(&ansi_map_originationtriggers_int_bool_val),0x10,
        "International (Int'l )", HFILL }},
	{ &hf_ansi_map_originationtriggers_wz,
      { "World Zone (WZ)", "ansi_map.originationtriggers.wz",
        FT_BOOLEAN, 8, TFS(&ansi_map_originationtriggers_wz_bool_val),0x20,
        "World Zone (WZ)", HFILL }},
	{ &hf_ansi_map_originationtriggers_unrec,
      { "Unrecognized Number (Unrec)", "ansi_map.originationtriggers.unrec",
        FT_BOOLEAN, 8, TFS(&ansi_map_originationtriggers_unrec_bool_val),0x40,
        "Unrecognized Number (Unrec)", HFILL }},
	{ &hf_ansi_map_originationtriggers_rvtc,
      { "Revertive Call (RvtC)", "ansi_map.originationtriggers.rvtc",
        FT_BOOLEAN, 8, TFS(&ansi_map_originationtriggers_rvtc_bool_val),0x80,
        "Revertive Call (RvtC)", HFILL }},
	{ &hf_ansi_map_originationtriggers_star,
      { "Star", "ansi_map.originationtriggers.star",
        FT_BOOLEAN, 8, TFS(&ansi_map_originationtriggers_star_bool_val),0x01,
        "Star", HFILL }},
	{ &hf_ansi_map_originationtriggers_ds,
      { "Double Star (DS)", "ansi_map.originationtriggers.ds",
        FT_BOOLEAN, 8, TFS(&ansi_map_originationtriggers_ds_bool_val),0x02,
        "Double Star (DS)", HFILL }},
	{ &hf_ansi_map_originationtriggers_pound,
      { "Pound", "ansi_map.originationtriggers.pound",
        FT_BOOLEAN, 8, TFS(&ansi_map_originationtriggers_pound_bool_val),0x04,
        "Pound", HFILL }},
	{ &hf_ansi_map_originationtriggers_dp,
      { "Double Pound (DP)", "ansi_map.originationtriggers.dp",
        FT_BOOLEAN, 8, TFS(&ansi_map_originationtriggers_dp_bool_val),0x08,
        "Double Pound (DP)", HFILL }},
	{ &hf_ansi_map_originationtriggers_pa,
      { "Prior Agreement (PA)", "ansi_map.originationtriggers.pa",
        FT_BOOLEAN, 8, TFS(&ansi_map_originationtriggers_pa_bool_val),0x10,
        "Prior Agreement (PA)", HFILL }},
	{ &hf_ansi_map_originationtriggers_nodig,
      { "No digits", "ansi_map.originationtriggers.nodig",
        FT_BOOLEAN, 8, TFS(&ansi_map_originationtriggers_nodig_bool_val),0x01,
        "No digits", HFILL }},
	{ &hf_ansi_map_originationtriggers_onedig,
      { "1 digit", "ansi_map.originationtriggers.onedig",
        FT_BOOLEAN, 8, TFS(&ansi_map_originationtriggers_onedig_bool_val),0x02,
        "1 digit", HFILL }},
	{ &hf_ansi_map_originationtriggers_twodig,
      { "2 digits", "ansi_map.originationtriggers.twodig",
        FT_BOOLEAN, 8, TFS(&ansi_map_originationtriggers_twodig_bool_val),0x04,
        "2 digits", HFILL }},
	{ &hf_ansi_map_originationtriggers_threedig,
      { "3 digits", "ansi_map.originationtriggers.threedig",
        FT_BOOLEAN, 8, TFS(&ansi_map_originationtriggers_threedig_bool_val),0x08,
        "3 digits", HFILL }},
	{ &hf_ansi_map_originationtriggers_fourdig,
      { "4 digits", "ansi_map.originationtriggers.fourdig",
        FT_BOOLEAN, 8, TFS(&ansi_map_originationtriggers_fourdig_bool_val),0x10,
        "4 digits", HFILL }},
	{ &hf_ansi_map_originationtriggers_fivedig,
      { "5 digits", "ansi_map.originationtriggers.fivedig",
        FT_BOOLEAN, 8, TFS(&ansi_map_originationtriggers_fivedig_bool_val),0x20,
        "5 digits", HFILL }},
	{ &hf_ansi_map_originationtriggers_sixdig,
      { "6 digits", "ansi_map.originationtriggers.sixdig",
        FT_BOOLEAN, 8, TFS(&ansi_map_originationtriggers_sixdig_bool_val),0x40,
        "6 digits", HFILL }},
	{ &hf_ansi_map_originationtriggers_sevendig,
      { "7 digits", "ansi_map.originationtriggers.sevendig",
        FT_BOOLEAN, 8, TFS(&ansi_map_originationtriggers_sevendig_bool_val),0x80,
        "7 digits", HFILL }},
	{ &hf_ansi_map_originationtriggers_eightdig,
      { "8 digits", "ansi_map.originationtriggers.eight",
        FT_BOOLEAN, 8, TFS(&ansi_map_originationtriggers_eightdig_bool_val),0x01,
        "8 digits", HFILL }},
	{ &hf_ansi_map_originationtriggers_ninedig,
      { "9 digits", "ansi_map.originationtriggers.nine",
        FT_BOOLEAN, 8, TFS(&ansi_map_originationtriggers_ninedig_bool_val),0x02,
        "9 digits", HFILL }},
	{ &hf_ansi_map_originationtriggers_tendig,
      { "10 digits", "ansi_map.originationtriggers.ten",
        FT_BOOLEAN, 8, TFS(&ansi_map_originationtriggers_tendig_bool_val),0x04,
        "10 digits", HFILL }},
	{ &hf_ansi_map_originationtriggers_elevendig,
      { "11 digits", "ansi_map.originationtriggers.eleven",
        FT_BOOLEAN, 8, TFS(&ansi_map_originationtriggers_elevendig_bool_val),0x08,
        "11 digits", HFILL }},
	{ &hf_ansi_map_originationtriggers_thwelvedig,
      { "12 digits", "ansi_map.originationtriggers.thwelv",
        FT_BOOLEAN, 8, TFS(&ansi_map_originationtriggers_thwelvdig_bool_val),0x10,
        "12 digits", HFILL }},
	{ &hf_ansi_map_originationtriggers_thirteendig,
      { "13 digits", "ansi_map.originationtriggers.thirteen",
        FT_BOOLEAN, 8, TFS(&ansi_map_originationtriggers_thirteendig_bool_val),0x20,
        "13 digits", HFILL }},
	{ &hf_ansi_map_originationtriggers_fourteendig,
      { "14 digits", "ansi_map.originationtriggers.fourteen",
        FT_BOOLEAN, 8, TFS(&ansi_map_originationtriggers_fourteendig_bool_val),0x40,
        "14 digits", HFILL }},
	{ &hf_ansi_map_originationtriggers_fifteendig,
      { "15 digits", "ansi_map.originationtriggers.fifteen",
        FT_BOOLEAN, 8, TFS(&ansi_map_originationtriggers_fifteendig_bool_val),0x80,
        "15 digits", HFILL }},

	{ &hf_ansi_map_triggercapability_init,
      { "Introducing Star/Pound (INIT)", "ansi_map.triggercapability.init",
        FT_BOOLEAN, 8, TFS(&ansi_map_triggercapability_bool_val),0x01,
        "Introducing Star/Pound (INIT)", HFILL }},
	{ &hf_ansi_map_triggercapability_kdigit,
      { "K-digit (K-digit)", "ansi_map.triggercapability.kdigit",
        FT_BOOLEAN, 8, TFS(&ansi_map_triggercapability_bool_val),0x02,
        "K-digit (K-digit)", HFILL }},
	{ &hf_ansi_map_triggercapability_all,
      { "All_Calls (All)", "ansi_map.triggercapability.all",
        FT_BOOLEAN, 8, TFS(&ansi_map_triggercapability_bool_val),0x04,
        "All_Calls (All)", HFILL }},
	{ &hf_ansi_map_triggercapability_rvtc,
      { "Revertive_Call (RvtC)", "ansi_map.triggercapability.rvtc",
        FT_BOOLEAN, 8, TFS(&ansi_map_triggercapability_bool_val),0x08,
        "Revertive_Call (RvtC)", HFILL }},
	{ &hf_ansi_map_triggercapability_oaa,
      { "Origination_Attempt_Authorized (OAA)", "ansi_map.triggercapability.oaa",
        FT_BOOLEAN, 8, TFS(&ansi_map_triggercapability_bool_val),0x10,
        "Origination_Attempt_Authorized (OAA)", HFILL }},
	{ &hf_ansi_map_triggercapability_oans,
      { "O_Answer (OANS)", "ansi_map.triggercapability.oans",
        FT_BOOLEAN, 8, TFS(&ansi_map_triggercapability_bool_val),0x20,
        "O_Answer (OANS)", HFILL }},
	{ &hf_ansi_map_triggercapability_odisc,
      { "O_Disconnect (ODISC)", "ansi_map.triggercapability.odisc",
        FT_BOOLEAN, 8, TFS(&ansi_map_triggercapability_bool_val),0x40,
        "O_Disconnect (ODISC)", HFILL }},
	{ &hf_ansi_map_triggercapability_ona,
      { "O_No_Answer (ONA)", "ansi_map.triggercapability.ona",
        FT_BOOLEAN, 8, TFS(&ansi_map_triggercapability_bool_val),0x80,
        "O_No_Answer (ONA)", HFILL }},

	{ &hf_ansi_map_triggercapability_ct ,
      { "Call Types (CT)", "ansi_map.triggercapability.ona",
        FT_BOOLEAN, 8, TFS(&ansi_map_triggercapability_bool_val),0x01,
        "Call Types (CT)", HFILL }},
	{ &hf_ansi_map_triggercapability_unrec,
      { "Unrecognized_Number (Unrec)", "ansi_map.triggercapability.unrec",
        FT_BOOLEAN, 8, TFS(&ansi_map_triggercapability_bool_val),0x02,
        "Unrecognized_Number (Unrec)", HFILL }},
	{ &hf_ansi_map_triggercapability_pa,
      { "Prior_Agreement (PA)", "ansi_map.triggercapability.pa",
        FT_BOOLEAN, 8, TFS(&ansi_map_triggercapability_bool_val),0x04,
        "Prior_Agreement (PA)", HFILL }},
	{ &hf_ansi_map_triggercapability_at,
      { "Advanced_Termination (AT)", "ansi_map.triggercapability.at",
        FT_BOOLEAN, 8, TFS(&ansi_map_triggercapability_bool_val),0x08,
        "Advanced_Termination (AT)", HFILL }},
	{ &hf_ansi_map_triggercapability_cgraa,
      { "Calling_Routing_Address_Available (CgRAA)", "ansi_map.triggercapability.cgraa",
        FT_BOOLEAN, 8, TFS(&ansi_map_triggercapability_bool_val),0x10,
        "Calling_Routing_Address_Available (CgRAA)", HFILL }},
	{ &hf_ansi_map_triggercapability_it,
      { "Initial_Termination (IT)", "ansi_map.triggercapability.it",
        FT_BOOLEAN, 8, TFS(&ansi_map_triggercapability_bool_val),0x20,
        "Initial_Termination (IT)", HFILL }},
	{ &hf_ansi_map_triggercapability_cdraa,
      { "Called_Routing_Address_Available (CdRAA)", "ansi_map.triggercapability.cdraa",
        FT_BOOLEAN, 8, TFS(&ansi_map_triggercapability_bool_val),0x40,
        "Called_Routing_Address_Available (CdRAA)", HFILL }},
	{ &hf_ansi_map_triggercapability_obsy,
      { "O_Called_Party_Busy (OBSY)", "ansi_map.triggercapability.ona",
        FT_BOOLEAN, 8, TFS(&ansi_map_triggercapability_bool_val),0x80,
        "O_Called_Party_Busy (OBSY)", HFILL }},

	{ &hf_ansi_map_triggercapability_tra ,
      { "Terminating_Resource_Available (TRA)", "ansi_map.triggercapability.tra",
        FT_BOOLEAN, 8, TFS(&ansi_map_triggercapability_bool_val),0x01,
        "Terminating_Resource_Available (TRA)", HFILL }},
	{ &hf_ansi_map_triggercapability_tbusy,
      { "T_Busy (TBusy)", "ansi_map.triggercapability.tbusy",
        FT_BOOLEAN, 8, TFS(&ansi_map_triggercapability_bool_val),0x02,
        "T_Busy (TBusy)", HFILL }},
	{ &hf_ansi_map_triggercapability_tna,
      { "T_No_Answer (TNA)", "ansi_map.triggercapability.tna",
        FT_BOOLEAN, 8, TFS(&ansi_map_triggercapability_bool_val),0x04,
        "T_No_Answer (TNA)", HFILL }},
	{ &hf_ansi_map_triggercapability_tans,
      { "T_Answer (TANS)", "ansi_map.triggercapability.tans",
        FT_BOOLEAN, 8, TFS(&ansi_map_triggercapability_bool_val),0x08,
        "T_Answer (TANS)", HFILL }},
	{ &hf_ansi_map_triggercapability_tdisc,
      { "T_Disconnect (TDISC) ", "ansi_map.triggercapability.tdisc",
        FT_BOOLEAN, 8, TFS(&ansi_map_triggercapability_bool_val),0x10,
        "T_Disconnect (TDISC) ", HFILL }},
	{ &hf_ansi_map_winoperationscapability_conn,
      { "ConnectResource (CONN)", "ansi_map.winoperationscapability.conn",
        FT_BOOLEAN, 8, TFS(&ansi_map_winoperationscapability_conn_bool_val),0x01,
        "ConnectResource (CONN)", HFILL }},
	{ &hf_ansi_map_winoperationscapability_ccdir,
      { "ConnectResource (CONN)", "ansi_map.winoperationscapability.ccdir",
        FT_BOOLEAN, 8, TFS(&ansi_map_winoperationscapability_ccdir_bool_val),0x02,
        "ConnectResource (CONN)", HFILL }},
	{ &hf_ansi_map_winoperationscapability_pos,
      { "ConnectResource (CONN)", "ansi_map.winoperationscapability.pos",
        FT_BOOLEAN, 8, TFS(&ansi_map_winoperationscapability_pos_bool_val),0x04,
        "ConnectResource (CONN)", HFILL }},
	{ &hf_ansi_map_pacaindicator_pa,
      { "Permanent Activation (PA)", "ansi_map.pacaindicator_pa",
        FT_BOOLEAN, 8, TFS(&ansi_map_pacaindicator_pa_bool_val),0x01,
        "Permanent Activation (PA)", HFILL }},
    { &hf_ansi_map_PACA_Level,
      { "PACA Level", "ansi_map.PACA_Level",
        FT_UINT8, BASE_DEC, VALS(ansi_map_PACA_Level_vals), 0x1e,
        "PACA Level", HFILL }},
		

/*--- Included file: packet-ansi_map-hfarr.c ---*/
#line 1 "packet-ansi_map-hfarr.c"
    { &hf_ansi_map_AuthenticationDirective_PDU,
      { "AuthenticationDirective", "ansi_map.AuthenticationDirective",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.AuthenticationDirective", HFILL }},
    { &hf_ansi_map_AuthenticationDirectiveRes_PDU,
      { "AuthenticationDirectiveRes", "ansi_map.AuthenticationDirectiveRes",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.AuthenticationDirectiveRes", HFILL }},
    { &hf_ansi_map_OriginationRequest_PDU,
      { "OriginationRequest", "ansi_map.OriginationRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.OriginationRequest", HFILL }},
    { &hf_ansi_map_OriginationRequestRes_PDU,
      { "OriginationRequestRes", "ansi_map.OriginationRequestRes",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.OriginationRequestRes", HFILL }},
    { &hf_ansi_map_invokeLast,
      { "invokeLast", "ansi_map.invokeLast",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.InvokePDU", HFILL }},
    { &hf_ansi_map_returnResultLast,
      { "returnResultLast", "ansi_map.returnResultLast",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.ReturnResultPDU", HFILL }},
    { &hf_ansi_map_returnError,
      { "returnError", "ansi_map.returnError",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.ReturnErrorPDU", HFILL }},
    { &hf_ansi_map_reject,
      { "reject", "ansi_map.reject",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.RejectPDU", HFILL }},
    { &hf_ansi_map_invokeNotLast,
      { "invokeNotLast", "ansi_map.invokeNotLast",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.InvokePDU", HFILL }},
    { &hf_ansi_map_returnResultNotLast,
      { "returnResultNotLast", "ansi_map.returnResultNotLast",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.ReturnResultPDU", HFILL }},
    { &hf_ansi_map_componentIDs,
      { "componentIDs", "ansi_map.componentIDs",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.OCTET_STRING_SIZE_0_2", HFILL }},
    { &hf_ansi_map_operationCode,
      { "operationCode", "ansi_map.operationCode",
        FT_UINT32, BASE_DEC, VALS(ansi_map_OperationCode_vals), 0,
        "ansi_map.OperationCode", HFILL }},
    { &hf_ansi_map_invokeParameters,
      { "invokeParameters", "ansi_map.invokeParameters",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.InvokeParameters", HFILL }},
    { &hf_ansi_map_componentID,
      { "componentID", "ansi_map.componentID",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.ComponentID", HFILL }},
    { &hf_ansi_map_returnResult,
      { "returnResult", "ansi_map.returnResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.ReturnParameters", HFILL }},
    { &hf_ansi_map_errorCode,
      { "errorCode", "ansi_map.errorCode",
        FT_UINT32, BASE_DEC, VALS(ansi_map_ErrorCode_vals), 0,
        "ansi_map.ErrorCode", HFILL }},
    { &hf_ansi_map_parameterre,
      { "parameterre", "ansi_map.parameterre",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.RejectParameters", HFILL }},
    { &hf_ansi_map_rejectProblem,
      { "rejectProblem", "ansi_map.rejectProblem",
        FT_INT32, BASE_DEC, VALS(ansi_map_ProblemPDU_vals), 0,
        "ansi_map.ProblemPDU", HFILL }},
    { &hf_ansi_map_parameterrj,
      { "parameterrj", "ansi_map.parameterrj",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.RejectParameters", HFILL }},
    { &hf_ansi_map_national,
      { "national", "ansi_map.national",
        FT_INT32, BASE_DEC, NULL, 0,
        "ansi_map.INTEGER_M32768_32767", HFILL }},
    { &hf_ansi_map_private,
      { "private", "ansi_map.private",
        FT_INT32, BASE_DEC, NULL, 0,
        "ansi_map.PrivateOperationCode", HFILL }},
    { &hf_ansi_map_nationaler,
      { "nationaler", "ansi_map.nationaler",
        FT_INT32, BASE_DEC, NULL, 0,
        "ansi_map.INTEGER_M32768_32767", HFILL }},
    { &hf_ansi_map_privateer,
      { "privateer", "ansi_map.privateer",
        FT_INT32, BASE_DEC, NULL, 0,
        "ansi_map.INTEGER", HFILL }},
    { &hf_ansi_map_electronicSerialNumber,
      { "electronicSerialNumber", "ansi_map.electronicSerialNumber",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.ElectronicSerialNumber", HFILL }},
    { &hf_ansi_map_msid,
      { "msid", "ansi_map.msid",
        FT_UINT32, BASE_DEC, VALS(ansi_map_MSID_vals), 0,
        "ansi_map.MSID", HFILL }},
    { &hf_ansi_map_authenticationAlgorithmVersion,
      { "authenticationAlgorithmVersion", "ansi_map.authenticationAlgorithmVersion",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.AuthenticationAlgorithmVersion", HFILL }},
    { &hf_ansi_map_authenticationResponseReauthentication,
      { "authenticationResponseReauthentication", "ansi_map.authenticationResponseReauthentication",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.AuthenticationResponseReauthentication", HFILL }},
    { &hf_ansi_map_authenticationResponseUniqueChallenge,
      { "authenticationResponseUniqueChallenge", "ansi_map.authenticationResponseUniqueChallenge",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.AuthenticationResponseUniqueChallenge", HFILL }},
    { &hf_ansi_map_callHistoryCount,
      { "callHistoryCount", "ansi_map.callHistoryCount",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ansi_map.CallHistoryCount", HFILL }},
    { &hf_ansi_map_cdmaPrivateLongCodeMask,
      { "cdmaPrivateLongCodeMask", "ansi_map.cdmaPrivateLongCodeMask",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.CDMAPrivateLongCodeMask", HFILL }},
    { &hf_ansi_map_carrierDigits,
      { "carrierDigits", "ansi_map.carrierDigits",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.CarrierDigits", HFILL }},
    { &hf_ansi_map_denyAccess,
      { "denyAccess", "ansi_map.denyAccess",
        FT_UINT32, BASE_DEC, VALS(ansi_map_DenyAccess_vals), 0,
        "ansi_map.DenyAccess", HFILL }},
    { &hf_ansi_map_destinationDigits,
      { "destinationDigits", "ansi_map.destinationDigits",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.DestinationDigits", HFILL }},
    { &hf_ansi_map_locationAreaID,
      { "locationAreaID", "ansi_map.locationAreaID",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.LocationAreaID", HFILL }},
    { &hf_ansi_map_randomVariableReauthentication,
      { "randomVariableReauthentication", "ansi_map.randomVariableReauthentication",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.RandomVariableReauthentication", HFILL }},
    { &hf_ansi_map_mobileStationMIN,
      { "mobileStationMIN", "ansi_map.mobileStationMIN",
        FT_NONE, BASE_DEC, NULL, 0,
        "ansi_map.MobileStationMIN", HFILL }},
    { &hf_ansi_map_mscid,
      { "mscid", "ansi_map.mscid",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.MSCID", HFILL }},
    { &hf_ansi_map_randomVariableSSD,
      { "randomVariableSSD", "ansi_map.randomVariableSSD",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.RandomVariableSSD", HFILL }},
    { &hf_ansi_map_randomVariableUniqueChallenge,
      { "randomVariableUniqueChallenge", "ansi_map.randomVariableUniqueChallenge",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.RandomVariableUniqueChallenge", HFILL }},
    { &hf_ansi_map_routingDigits,
      { "routingDigits", "ansi_map.routingDigits",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.RoutingDigits", HFILL }},
    { &hf_ansi_map_senderIdentificationNumber,
      { "senderIdentificationNumber", "ansi_map.senderIdentificationNumber",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.SenderIdentificationNumber", HFILL }},
    { &hf_ansi_map_sharedSecretData,
      { "sharedSecretData", "ansi_map.sharedSecretData",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.SharedSecretData", HFILL }},
    { &hf_ansi_map_signalingMessageEncryptionKey,
      { "signalingMessageEncryptionKey", "ansi_map.signalingMessageEncryptionKey",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.SignalingMessageEncryptionKey", HFILL }},
    { &hf_ansi_map_ssdnotShared,
      { "ssdnotShared", "ansi_map.ssdnotShared",
        FT_UINT32, BASE_DEC, VALS(ansi_map_SSDNotShared_vals), 0,
        "ansi_map.SSDNotShared", HFILL }},
    { &hf_ansi_map_updateCount,
      { "updateCount", "ansi_map.updateCount",
        FT_UINT32, BASE_DEC, VALS(ansi_map_UpdateCount_vals), 0,
        "ansi_map.UpdateCount", HFILL }},
    { &hf_ansi_map_interMSCCircuitID,
      { "interMSCCircuitID", "ansi_map.interMSCCircuitID",
        FT_NONE, BASE_DEC, NULL, 0,
        "ansi_map.InterMSCCircuitID", HFILL }},
    { &hf_ansi_map_mobileIdentificationNumber,
      { "mobileIdentificationNumber", "ansi_map.mobileIdentificationNumber",
        FT_NONE, BASE_DEC, NULL, 0,
        "ansi_map.MobileIdentificationNumber", HFILL }},
    { &hf_ansi_map_countUpdateReport,
      { "countUpdateReport", "ansi_map.countUpdateReport",
        FT_UINT8, BASE_DEC, VALS(ansi_map_CountUpdateReport_vals), 0,
        "ansi_map.CountUpdateReport", HFILL }},
    { &hf_ansi_map_uniqueChallengeReport,
      { "uniqueChallengeReport", "ansi_map.uniqueChallengeReport",
        FT_UINT8, BASE_DEC, VALS(ansi_map_UniqueChallengeReport_vals), 0,
        "ansi_map.UniqueChallengeReport", HFILL }},
    { &hf_ansi_map_reportType,
      { "reportType", "ansi_map.reportType",
        FT_UINT32, BASE_DEC, VALS(ansi_map_ReportType_vals), 0,
        "ansi_map.ReportType", HFILL }},
    { &hf_ansi_map_systemAccessType,
      { "systemAccessType", "ansi_map.systemAccessType",
        FT_UINT32, BASE_DEC, VALS(ansi_map_SystemAccessType_vals), 0,
        "ansi_map.SystemAccessType", HFILL }},
    { &hf_ansi_map_systemCapabilities,
      { "systemCapabilities", "ansi_map.systemCapabilities",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.SystemCapabilities", HFILL }},
    { &hf_ansi_map_callHistoryCountExpected,
      { "callHistoryCountExpected", "ansi_map.callHistoryCountExpected",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ansi_map.CallHistoryCountExpected", HFILL }},
    { &hf_ansi_map_reportType2,
      { "reportType2", "ansi_map.reportType2",
        FT_UINT32, BASE_DEC, VALS(ansi_map_ReportType_vals), 0,
        "ansi_map.ReportType", HFILL }},
    { &hf_ansi_map_terminalType,
      { "terminalType", "ansi_map.terminalType",
        FT_UINT32, BASE_DEC, VALS(ansi_map_TerminalType_vals), 0,
        "ansi_map.TerminalType", HFILL }},
    { &hf_ansi_map_authenticationData,
      { "authenticationData", "ansi_map.authenticationData",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.AuthenticationData", HFILL }},
    { &hf_ansi_map_authenticationResponse,
      { "authenticationResponse", "ansi_map.authenticationResponse",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.AuthenticationResponse", HFILL }},
    { &hf_ansi_map_cdmaNetworkIdentification,
      { "cdmaNetworkIdentification", "ansi_map.cdmaNetworkIdentification",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.CDMANetworkIdentification", HFILL }},
    { &hf_ansi_map_confidentialityModes,
      { "confidentialityModes", "ansi_map.confidentialityModes",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.ConfidentialityModes", HFILL }},
    { &hf_ansi_map_controlChannelMode,
      { "controlChannelMode", "ansi_map.controlChannelMode",
        FT_UINT8, BASE_DEC, VALS(ansi_map_ControlChannelMode_vals), 0,
        "ansi_map.ControlChannelMode", HFILL }},
    { &hf_ansi_map_digits,
      { "digits", "ansi_map.digits",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.Digits", HFILL }},
    { &hf_ansi_map_pc_ssn,
      { "pc-ssn", "ansi_map.pc_ssn",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.PC_SSN", HFILL }},
    { &hf_ansi_map_randomVariable,
      { "randomVariable", "ansi_map.randomVariable",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.RandomVariable", HFILL }},
    { &hf_ansi_map_serviceRedirectionCause,
      { "serviceRedirectionCause", "ansi_map.serviceRedirectionCause",
        FT_UINT8, BASE_DEC, VALS(ansi_map_ServiceRedirectionCause_type_vals), 0,
        "ansi_map.ServiceRedirectionCause", HFILL }},
    { &hf_ansi_map_suspiciousAccess,
      { "suspiciousAccess", "ansi_map.suspiciousAccess",
        FT_UINT32, BASE_DEC, VALS(ansi_map_SuspiciousAccess_vals), 0,
        "ansi_map.SuspiciousAccess", HFILL }},
    { &hf_ansi_map_transactionCapability,
      { "transactionCapability", "ansi_map.transactionCapability",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.TransactionCapability", HFILL }},
    { &hf_ansi_map_analogRedirectRecord,
      { "analogRedirectRecord", "ansi_map.analogRedirectRecord",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.AnalogRedirectRecord", HFILL }},
    { &hf_ansi_map_cdmaRedirectRecord,
      { "cdmaRedirectRecord", "ansi_map.cdmaRedirectRecord",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.CDMARedirectRecord", HFILL }},
    { &hf_ansi_map_dataKey,
      { "dataKey", "ansi_map.dataKey",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.DataKey", HFILL }},
    { &hf_ansi_map_roamingIndication,
      { "roamingIndication", "ansi_map.roamingIndication",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.RoamingIndication", HFILL }},
    { &hf_ansi_map_serviceRedirectionInfo,
      { "serviceRedirectionInfo", "ansi_map.serviceRedirectionInfo",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.ServiceRedirectionInfo", HFILL }},
    { &hf_ansi_map_voicePrivacyMask,
      { "voicePrivacyMask", "ansi_map.voicePrivacyMask",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.VoicePrivacyMask", HFILL }},
    { &hf_ansi_map_reauthenticationReport,
      { "reauthenticationReport", "ansi_map.reauthenticationReport",
        FT_UINT8, BASE_DEC, VALS(ansi_map_ReauthenticationReport_vals), 0,
        "ansi_map.ReauthenticationReport", HFILL }},
    { &hf_ansi_map_serviceIndicator,
      { "serviceIndicator", "ansi_map.serviceIndicator",
        FT_UINT8, BASE_DEC, VALS(ansi_map_ServiceIndicator_vals), 0,
        "ansi_map.ServiceIndicator", HFILL }},
    { &hf_ansi_map_signalingMessageEncryptionReport,
      { "signalingMessageEncryptionReport", "ansi_map.signalingMessageEncryptionReport",
        FT_UINT8, BASE_DEC, VALS(ansi_map_SMEReport_vals), 0,
        "ansi_map.SignalingMessageEncryptionReport", HFILL }},
    { &hf_ansi_map_ssdUpdateReport,
      { "ssdUpdateReport", "ansi_map.ssdUpdateReport",
        FT_UINT16, BASE_DEC, VALS(ansi_map_SSDUpdateReport_vals), 0,
        "ansi_map.SSDUpdateReport", HFILL }},
    { &hf_ansi_map_voicePrivacyReport,
      { "voicePrivacyReport", "ansi_map.voicePrivacyReport",
        FT_UINT8, BASE_DEC, VALS(ansi_map_VoicePrivacyReport_vals), 0,
        "ansi_map.VoicePrivacyReport", HFILL }},
    { &hf_ansi_map_randomVariableBaseStation,
      { "randomVariableBaseStation", "ansi_map.randomVariableBaseStation",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.RandomVariableBaseStation", HFILL }},
    { &hf_ansi_map_authenticationResponseBaseStation,
      { "authenticationResponseBaseStation", "ansi_map.authenticationResponseBaseStation",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.AuthenticationResponseBaseStation", HFILL }},
    { &hf_ansi_map_billingID,
      { "billingID", "ansi_map.billingID",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.BillingID", HFILL }},
    { &hf_ansi_map_channelData,
      { "channelData", "ansi_map.channelData",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.ChannelData", HFILL }},
    { &hf_ansi_map_interSwitchCount,
      { "interSwitchCount", "ansi_map.interSwitchCount",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ansi_map.InterSwitchCount", HFILL }},
    { &hf_ansi_map_servingCellID,
      { "servingCellID", "ansi_map.servingCellID",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.ServingCellID", HFILL }},
    { &hf_ansi_map_stationClassMark,
      { "stationClassMark", "ansi_map.stationClassMark",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.StationClassMark", HFILL }},
    { &hf_ansi_map_targetCellID,
      { "targetCellID", "ansi_map.targetCellID",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.TargetCellID", HFILL }},
    { &hf_ansi_map_handoffReason,
      { "handoffReason", "ansi_map.handoffReason",
        FT_UINT32, BASE_DEC, VALS(ansi_map_HandoffReason_vals), 0,
        "ansi_map.HandoffReason", HFILL }},
    { &hf_ansi_map_handoffState,
      { "handoffState", "ansi_map.handoffState",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.HandoffState", HFILL }},
    { &hf_ansi_map_tdmaBurstIndicator,
      { "tdmaBurstIndicator", "ansi_map.tdmaBurstIndicator",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.TDMABurstIndicator", HFILL }},
    { &hf_ansi_map_tdmaCallMode,
      { "tdmaCallMode", "ansi_map.tdmaCallMode",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.TDMACallMode", HFILL }},
    { &hf_ansi_map_tdmaChannelData,
      { "tdmaChannelData", "ansi_map.tdmaChannelData",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.TDMAChannelData", HFILL }},
    { &hf_ansi_map_baseStationManufacturerCode,
      { "baseStationManufacturerCode", "ansi_map.baseStationManufacturerCode",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.BaseStationManufacturerCode", HFILL }},
    { &hf_ansi_map_alertCode,
      { "alertCode", "ansi_map.alertCode",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.AlertCode", HFILL }},
    { &hf_ansi_map_cdma2000HandoffInvokeIOSData,
      { "cdma2000HandoffInvokeIOSData", "ansi_map.cdma2000HandoffInvokeIOSData",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.CDMA2000HandoffInvokeIOSData", HFILL }},
    { &hf_ansi_map_cdmaCallMode,
      { "cdmaCallMode", "ansi_map.cdmaCallMode",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.CDMACallMode", HFILL }},
    { &hf_ansi_map_cdmaChannelData,
      { "cdmaChannelData", "ansi_map.cdmaChannelData",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.CDMAChannelData", HFILL }},
    { &hf_ansi_map_cdmaConnectionReferenceList,
      { "cdmaConnectionReferenceList", "ansi_map.cdmaConnectionReferenceList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ansi_map.CDMAConnectionReferenceList", HFILL }},
    { &hf_ansi_map_cdmaMobileProtocolRevision,
      { "cdmaMobileProtocolRevision", "ansi_map.cdmaMobileProtocolRevision",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.CDMAMobileProtocolRevision", HFILL }},
    { &hf_ansi_map_cdmaMSMeasuredChannelIdentity,
      { "cdmaMSMeasuredChannelIdentity", "ansi_map.cdmaMSMeasuredChannelIdentity",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.CDMAMSMeasuredChannelIdentity", HFILL }},
    { &hf_ansi_map_cdmaServiceConfigurationRecord,
      { "cdmaServiceConfigurationRecord", "ansi_map.cdmaServiceConfigurationRecord",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.CDMAServiceConfigurationRecord", HFILL }},
    { &hf_ansi_map_cdmaServiceOptionList,
      { "cdmaServiceOptionList", "ansi_map.cdmaServiceOptionList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ansi_map.CDMAServiceOptionList", HFILL }},
    { &hf_ansi_map_cdmaServingOneWayDelay,
      { "cdmaServingOneWayDelay", "ansi_map.cdmaServingOneWayDelay",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.CDMAServingOneWayDelay", HFILL }},
    { &hf_ansi_map_cdmaStationClassMark,
      { "cdmaStationClassMark", "ansi_map.cdmaStationClassMark",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.CDMAStationClassMark", HFILL }},
    { &hf_ansi_map_cdmaStationClassMark2,
      { "cdmaStationClassMark2", "ansi_map.cdmaStationClassMark2",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.CDMAStationClassMark2", HFILL }},
    { &hf_ansi_map_cdmaTargetMAHOList,
      { "cdmaTargetMAHOList", "ansi_map.cdmaTargetMAHOList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ansi_map.CDMATargetMAHOList", HFILL }},
    { &hf_ansi_map_cdmaTargetMeasurementList,
      { "cdmaTargetMeasurementList", "ansi_map.cdmaTargetMeasurementList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ansi_map.CDMATargetMeasurementList", HFILL }},
    { &hf_ansi_map_dataPrivacyParameters,
      { "dataPrivacyParameters", "ansi_map.dataPrivacyParameters",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.DataPrivacyParameters", HFILL }},
    { &hf_ansi_map_ilspInformation,
      { "ilspInformation", "ansi_map.ilspInformation",
        FT_UINT8, BASE_DEC, VALS(ansi_map_islp_type_vals), 0,
        "ansi_map.ISLPInformation", HFILL }},
    { &hf_ansi_map_msLocation,
      { "msLocation", "ansi_map.msLocation",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.MSLocation", HFILL }},
    { &hf_ansi_map_nampsCallMode,
      { "nampsCallMode", "ansi_map.nampsCallMode",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.NAMPSCallMode", HFILL }},
    { &hf_ansi_map_nampsChannelData,
      { "nampsChannelData", "ansi_map.nampsChannelData",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.NAMPSChannelData", HFILL }},
    { &hf_ansi_map_nonPublicData,
      { "nonPublicData", "ansi_map.nonPublicData",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.NonPublicData", HFILL }},
    { &hf_ansi_map_pdsnAddress,
      { "pdsnAddress", "ansi_map.pdsnAddress",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.PDSNAddress", HFILL }},
    { &hf_ansi_map_pdsnProtocolType,
      { "pdsnProtocolType", "ansi_map.pdsnProtocolType",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.PDSNProtocolType", HFILL }},
    { &hf_ansi_map_qosPriority,
      { "qosPriority", "ansi_map.qosPriority",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.QoSPriority", HFILL }},
    { &hf_ansi_map_systemOperatorCode,
      { "systemOperatorCode", "ansi_map.systemOperatorCode",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.SystemOperatorCode", HFILL }},
    { &hf_ansi_map_tdmaBandwidth,
      { "tdmaBandwidth", "ansi_map.tdmaBandwidth",
        FT_UINT8, BASE_DEC, VALS(ansi_map_TDMABandwidth_vals), 0x0f,
        "ansi_map.TDMABandwidth", HFILL }},
    { &hf_ansi_map_tdmaServiceCode,
      { "tdmaServiceCode", "ansi_map.tdmaServiceCode",
        FT_UINT8, BASE_DEC, VALS(ansi_map_TDMAServiceCode_vals), 0,
        "ansi_map.TDMAServiceCode", HFILL }},
    { &hf_ansi_map_tdmaTerminalCapability,
      { "tdmaTerminalCapability", "ansi_map.tdmaTerminalCapability",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.TDMATerminalCapability", HFILL }},
    { &hf_ansi_map_tdmaVoiceCoder,
      { "tdmaVoiceCoder", "ansi_map.tdmaVoiceCoder",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.TDMAVoiceCoder", HFILL }},
    { &hf_ansi_map_userZoneData,
      { "userZoneData", "ansi_map.userZoneData",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.UserZoneData", HFILL }},
    { &hf_ansi_map_bsmcstatus,
      { "bsmcstatus", "ansi_map.bsmcstatus",
        FT_UINT8, BASE_DEC, VALS(ansi_map_BSMCStatus_vals), 0x03,
        "ansi_map.BSMCStatus", HFILL }},
    { &hf_ansi_map_cdma2000HandoffResponseIOSData,
      { "cdma2000HandoffResponseIOSData", "ansi_map.cdma2000HandoffResponseIOSData",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.CDMA2000HandoffResponseIOSData", HFILL }},
    { &hf_ansi_map_cdmaCodeChannelList,
      { "cdmaCodeChannelList", "ansi_map.cdmaCodeChannelList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ansi_map.CDMACodeChannelList", HFILL }},
    { &hf_ansi_map_cdmaSearchParameters,
      { "cdmaSearchParameters", "ansi_map.cdmaSearchParameters",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.CDMASearchParameters", HFILL }},
    { &hf_ansi_map_cdmaSearchWindow,
      { "cdmaSearchWindow", "ansi_map.cdmaSearchWindow",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.CDMASearchWindow", HFILL }},
    { &hf_ansi_map_sOCStatus,
      { "sOCStatus", "ansi_map.sOCStatus",
        FT_UINT8, BASE_DEC, VALS(ansi_map_SOCStatus_vals), 0x03,
        "ansi_map.SOCStatus", HFILL }},
    { &hf_ansi_map_releaseReason,
      { "releaseReason", "ansi_map.releaseReason",
        FT_UINT32, BASE_DEC, VALS(ansi_map_ReleaseReason_vals), 0,
        "ansi_map.ReleaseReason", HFILL }},
    { &hf_ansi_map_acgencountered,
      { "acgencountered", "ansi_map.acgencountered",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.ACGEncountered", HFILL }},
    { &hf_ansi_map_callingPartyName,
      { "callingPartyName", "ansi_map.callingPartyName",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.CallingPartyName", HFILL }},
    { &hf_ansi_map_callingPartyNumberDigits1,
      { "callingPartyNumberDigits1", "ansi_map.callingPartyNumberDigits1",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.CallingPartyNumberDigits1", HFILL }},
    { &hf_ansi_map_callingPartyNumberDigits2,
      { "callingPartyNumberDigits2", "ansi_map.callingPartyNumberDigits2",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.CallingPartyNumberDigits2", HFILL }},
    { &hf_ansi_map_callingPartySubaddress,
      { "callingPartySubaddress", "ansi_map.callingPartySubaddress",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.CallingPartySubaddress", HFILL }},
    { &hf_ansi_map_conferenceCallingIndicator,
      { "conferenceCallingIndicator", "ansi_map.conferenceCallingIndicator",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.ConferenceCallingIndicator", HFILL }},
    { &hf_ansi_map_mobileDirectoryNumber,
      { "mobileDirectoryNumber", "ansi_map.mobileDirectoryNumber",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.MobileDirectoryNumber", HFILL }},
    { &hf_ansi_map_mSCIdentificationNumber,
      { "mSCIdentificationNumber", "ansi_map.mSCIdentificationNumber",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.MSCIdentificationNumber", HFILL }},
    { &hf_ansi_map_oneTimeFeatureIndicator,
      { "oneTimeFeatureIndicator", "ansi_map.oneTimeFeatureIndicator",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.OneTimeFeatureIndicator", HFILL }},
    { &hf_ansi_map_featureResult,
      { "featureResult", "ansi_map.featureResult",
        FT_UINT32, BASE_DEC, VALS(ansi_map_FeatureResult_vals), 0,
        "ansi_map.FeatureResult", HFILL }},
    { &hf_ansi_map_accessDeniedReason,
      { "accessDeniedReason", "ansi_map.accessDeniedReason",
        FT_UINT32, BASE_DEC, VALS(ansi_map_AccessDeniedReason_vals), 0,
        "ansi_map.AccessDeniedReason", HFILL }},
    { &hf_ansi_map_actionCode,
      { "actionCode", "ansi_map.actionCode",
        FT_UINT8, BASE_DEC, VALS(ansi_map_ActionCode_vals), 0,
        "ansi_map.ActionCode", HFILL }},
    { &hf_ansi_map_announcementList,
      { "announcementList", "ansi_map.announcementList",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.AnnouncementList", HFILL }},
    { &hf_ansi_map_callingPartyNumberString1,
      { "callingPartyNumberString1", "ansi_map.callingPartyNumberString1",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.CallingPartyNumberString1", HFILL }},
    { &hf_ansi_map_callingPartyNumberString2,
      { "callingPartyNumberString2", "ansi_map.callingPartyNumberString2",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.CallingPartyNumberString2", HFILL }},
    { &hf_ansi_map_digits_Destination,
      { "digits-Destination", "ansi_map.digits_Destination",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.Digits", HFILL }},
    { &hf_ansi_map_displayText,
      { "displayText", "ansi_map.displayText",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.DisplayText", HFILL }},
    { &hf_ansi_map_displayText2,
      { "displayText2", "ansi_map.displayText2",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.DisplayText2", HFILL }},
    { &hf_ansi_map_dmh_AccountCodeDigits,
      { "dmh-AccountCodeDigits", "ansi_map.dmh_AccountCodeDigits",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.DMH_AccountCodeDigits", HFILL }},
    { &hf_ansi_map_dmh_AlternateBillingDigits,
      { "dmh-AlternateBillingDigits", "ansi_map.dmh_AlternateBillingDigits",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.DMH_AlternateBillingDigits", HFILL }},
    { &hf_ansi_map_dmh_BillingDigits,
      { "dmh-BillingDigits", "ansi_map.dmh_BillingDigits",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.DMH_BillingDigits", HFILL }},
    { &hf_ansi_map_dmh_RedirectionIndicator,
      { "dmh-RedirectionIndicator", "ansi_map.dmh_RedirectionIndicator",
        FT_UINT32, BASE_DEC, VALS(ansi_map_DMH_RedirectionIndicator_vals), 0,
        "ansi_map.DMH_RedirectionIndicator", HFILL }},
    { &hf_ansi_map_groupInformation,
      { "groupInformation", "ansi_map.groupInformation",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.GroupInformation", HFILL }},
    { &hf_ansi_map_noAnswerTime,
      { "noAnswerTime", "ansi_map.noAnswerTime",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.NoAnswerTime", HFILL }},
    { &hf_ansi_map_pACAIndicator,
      { "pACAIndicator", "ansi_map.pACAIndicator",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.PACAIndicator", HFILL }},
    { &hf_ansi_map_pilotNumber,
      { "pilotNumber", "ansi_map.pilotNumber",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.PilotNumber", HFILL }},
    { &hf_ansi_map_preferredLanguageIndicator,
      { "preferredLanguageIndicator", "ansi_map.preferredLanguageIndicator",
        FT_UINT8, BASE_DEC, VALS(ansi_map_PreferredLanguageIndicator_vals), 0,
        "ansi_map.PreferredLanguageIndicator", HFILL }},
    { &hf_ansi_map_redirectingNumberDigits,
      { "redirectingNumberDigits", "ansi_map.redirectingNumberDigits",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.RedirectingNumberDigits", HFILL }},
    { &hf_ansi_map_redirectingNumberString,
      { "redirectingNumberString", "ansi_map.redirectingNumberString",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.RedirectingNumberString", HFILL }},
    { &hf_ansi_map_redirectingSubaddress,
      { "redirectingSubaddress", "ansi_map.redirectingSubaddress",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.RedirectingSubaddress", HFILL }},
    { &hf_ansi_map_resumePIC,
      { "resumePIC", "ansi_map.resumePIC",
        FT_UINT32, BASE_DEC, VALS(ansi_map_ResumePIC_vals), 0,
        "ansi_map.ResumePIC", HFILL }},
    { &hf_ansi_map_terminationList,
      { "terminationList", "ansi_map.terminationList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ansi_map.TerminationList", HFILL }},
    { &hf_ansi_map_terminationTriggers,
      { "terminationTriggers", "ansi_map.terminationTriggers",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.TerminationTriggers", HFILL }},
    { &hf_ansi_map_triggerAddressList,
      { "triggerAddressList", "ansi_map.triggerAddressList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ansi_map.TriggerAddressList", HFILL }},
    { &hf_ansi_map_targetCellIDList,
      { "targetCellIDList", "ansi_map.targetCellIDList",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.TargetCellIDList", HFILL }},
    { &hf_ansi_map_signalQuality,
      { "signalQuality", "ansi_map.signalQuality",
        FT_UINT32, BASE_DEC, VALS(ansi_map_SignalQuality_vals), 0,
        "ansi_map.SignalQuality", HFILL }},
    { &hf_ansi_map_targetMeasurementList,
      { "targetMeasurementList", "ansi_map.targetMeasurementList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ansi_map.TargetMeasurementList", HFILL }},
    { &hf_ansi_map_alertResult,
      { "alertResult", "ansi_map.alertResult",
        FT_UINT8, BASE_DEC, VALS(ansi_map_AlertResult_result_vals), 0,
        "ansi_map.AlertResult", HFILL }},
    { &hf_ansi_map_messageWaitingNotificationCount,
      { "messageWaitingNotificationCount", "ansi_map.messageWaitingNotificationCount",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.MessageWaitingNotificationCount", HFILL }},
    { &hf_ansi_map_messageWaitingNotificationType,
      { "messageWaitingNotificationType", "ansi_map.messageWaitingNotificationType",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.MessageWaitingNotificationType", HFILL }},
    { &hf_ansi_map_cdmaBandClass,
      { "cdmaBandClass", "ansi_map.cdmaBandClass",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.CDMABandClass", HFILL }},
    { &hf_ansi_map_cdmaServiceOption,
      { "cdmaServiceOption", "ansi_map.cdmaServiceOption",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.CDMAServiceOption", HFILL }},
    { &hf_ansi_map_cdmaSlotCycleIndex,
      { "cdmaSlotCycleIndex", "ansi_map.cdmaSlotCycleIndex",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.CDMASlotCycleIndex", HFILL }},
    { &hf_ansi_map_extendedMSCID,
      { "extendedMSCID", "ansi_map.extendedMSCID",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.ExtendedMSCID", HFILL }},
    { &hf_ansi_map_extendedSystemMyTypeCode,
      { "extendedSystemMyTypeCode", "ansi_map.extendedSystemMyTypeCode",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.ExtendedSystemMyTypeCode", HFILL }},
    { &hf_ansi_map_imsi,
      { "imsi", "ansi_map.imsi",
        FT_BYTES, BASE_HEX, NULL, 0,
        "gsm_map.IMSI", HFILL }},
    { &hf_ansi_map_legInformation,
      { "legInformation", "ansi_map.legInformation",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.LegInformation", HFILL }},
    { &hf_ansi_map_mSIDUsage,
      { "mSIDUsage", "ansi_map.mSIDUsage",
        FT_UINT8, BASE_DEC, VALS(ansi_MSIDUsage_m_or_i_vals), 0x03,
        "ansi_map.MSIDUsage", HFILL }},
    { &hf_ansi_map_networkTMSI,
      { "networkTMSI", "ansi_map.networkTMSI",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.NetworkTMSI", HFILL }},
    { &hf_ansi_map_pageCount,
      { "pageCount", "ansi_map.pageCount",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.PageCount", HFILL }},
    { &hf_ansi_map_pageIndicator,
      { "pageIndicator", "ansi_map.pageIndicator",
        FT_UINT8, BASE_DEC, VALS(ansi_map_PageIndicator_vals), 0,
        "ansi_map.PageIndicator", HFILL }},
    { &hf_ansi_map_pageResponseTime,
      { "pageResponseTime", "ansi_map.pageResponseTime",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.PageResponseTime", HFILL }},
    { &hf_ansi_map_pilotBillingID,
      { "pilotBillingID", "ansi_map.pilotBillingID",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.PilotBillingID", HFILL }},
    { &hf_ansi_map_redirectingPartyName,
      { "redirectingPartyName", "ansi_map.redirectingPartyName",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.RedirectingPartyName", HFILL }},
    { &hf_ansi_map_systemMyTypeCode,
      { "systemMyTypeCode", "ansi_map.systemMyTypeCode",
        FT_UINT32, BASE_DEC, VALS(ansi_map_SystemMyTypeCode_vals), 0,
        "ansi_map.SystemMyTypeCode", HFILL }},
    { &hf_ansi_map_tdmaDataFeaturesIndicator,
      { "tdmaDataFeaturesIndicator", "ansi_map.tdmaDataFeaturesIndicator",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.TDMADataFeaturesIndicator", HFILL }},
    { &hf_ansi_map_terminationTreatment,
      { "terminationTreatment", "ansi_map.terminationTreatment",
        FT_UINT8, BASE_DEC, VALS(ansi_map_TerminationTreatment_vals), 0,
        "ansi_map.TerminationTreatment", HFILL }},
    { &hf_ansi_map_conditionallyDeniedReason,
      { "conditionallyDeniedReason", "ansi_map.conditionallyDeniedReason",
        FT_UINT32, BASE_DEC, VALS(ansi_map_ConditionallyDeniedReason_vals), 0,
        "ansi_map.ConditionallyDeniedReason", HFILL }},
    { &hf_ansi_map_pagingFrameClass,
      { "pagingFrameClass", "ansi_map.pagingFrameClass",
        FT_UINT8, BASE_DEC, VALS(ansi_map_PagingFrameClass_vals), 0x03,
        "ansi_map.PagingFrameClass", HFILL }},
    { &hf_ansi_map_pSID_RSIDList,
      { "pSID-RSIDList", "ansi_map.pSID_RSIDList",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.PSID_RSIDList", HFILL }},
    { &hf_ansi_map_randc,
      { "randc", "ansi_map.randc",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.RANDC", HFILL }},
    { &hf_ansi_map_tdmaDataMode,
      { "tdmaDataMode", "ansi_map.tdmaDataMode",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.TDMADataMode", HFILL }},
    { &hf_ansi_map_changeServiceAttributes,
      { "changeServiceAttributes", "ansi_map.changeServiceAttributes",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.ChangeServiceAttributes", HFILL }},
    { &hf_ansi_map_edirectingSubaddress,
      { "edirectingSubaddress", "ansi_map.edirectingSubaddress",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.RedirectingSubaddress", HFILL }},
    { &hf_ansi_map_setupResult,
      { "setupResult", "ansi_map.setupResult",
        FT_UINT8, BASE_DEC, VALS(ansi_map_SetupResult_vals), 0,
        "ansi_map.SetupResult", HFILL }},
    { &hf_ansi_map_terminationAccessType,
      { "terminationAccessType", "ansi_map.terminationAccessType",
        FT_UINT8, BASE_DEC, VALS(ansi_map_TerminationAccessType_vals), 0,
        "ansi_map.TerminationAccessType", HFILL }},
    { &hf_ansi_map_triggerType,
      { "triggerType", "ansi_map.triggerType",
        FT_UINT32, BASE_DEC, VALS(ansi_map_TriggerType_vals), 0,
        "ansi_map.TriggerType", HFILL }},
    { &hf_ansi_map_winCapability,
      { "winCapability", "ansi_map.winCapability",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.WINCapability", HFILL }},
    { &hf_ansi_map_callingPartyCategory,
      { "callingPartyCategory", "ansi_map.callingPartyCategory",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.CallingPartyCategory", HFILL }},
    { &hf_ansi_map_controlNetworkID,
      { "controlNetworkID", "ansi_map.controlNetworkID",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.ControlNetworkID", HFILL }},
    { &hf_ansi_map_digits_carrier,
      { "digits-carrier", "ansi_map.digits_carrier",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.Digits", HFILL }},
    { &hf_ansi_map_digits_dest,
      { "digits-dest", "ansi_map.digits_dest",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.Digits", HFILL }},
    { &hf_ansi_map_dmh_ServiceID,
      { "dmh-ServiceID", "ansi_map.dmh_ServiceID",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.DMH_ServiceID", HFILL }},
    { &hf_ansi_map_edirectingNumberDigits,
      { "edirectingNumberDigits", "ansi_map.edirectingNumberDigits",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.RedirectingNumberDigits", HFILL }},
    { &hf_ansi_map_lectronicSerialNumber,
      { "lectronicSerialNumber", "ansi_map.lectronicSerialNumber",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.ElectronicSerialNumber", HFILL }},
    { &hf_ansi_map_deregistrationType,
      { "deregistrationType", "ansi_map.deregistrationType",
        FT_UINT32, BASE_DEC, VALS(ansi_map_DeregistrationType_vals), 0,
        "ansi_map.DeregistrationType", HFILL }},
    { &hf_ansi_map_servicesResult,
      { "servicesResult", "ansi_map.servicesResult",
        FT_UINT8, BASE_DEC, VALS(ansi_map_ServicesResult_ppr_vals), 0x03,
        "ansi_map.ServicesResult", HFILL }},
    { &hf_ansi_map_sms_MessageWaitingIndicator,
      { "sms-MessageWaitingIndicator", "ansi_map.sms_MessageWaitingIndicator",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.SMS_MessageWaitingIndicator", HFILL }},
    { &hf_ansi_map_originationTriggers,
      { "originationTriggers", "ansi_map.originationTriggers",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.OriginationTriggers", HFILL }},
    { &hf_ansi_map_featureIndicator,
      { "featureIndicator", "ansi_map.featureIndicator",
        FT_UINT32, BASE_DEC, VALS(ansi_map_FeatureIndicator_vals), 0,
        "ansi_map.FeatureIndicator", HFILL }},
    { &hf_ansi_map_dmh_ChargeInformation,
      { "dmh-ChargeInformation", "ansi_map.dmh_ChargeInformation",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.DMH_ChargeInformation", HFILL }},
    { &hf_ansi_map_qualificationInformationCode,
      { "qualificationInformationCode", "ansi_map.qualificationInformationCode",
        FT_UINT32, BASE_DEC, VALS(ansi_map_QualificationInformationCode_vals), 0,
        "ansi_map.QualificationInformationCode", HFILL }},
    { &hf_ansi_map_authorizationDenied,
      { "authorizationDenied", "ansi_map.authorizationDenied",
        FT_UINT32, BASE_DEC, VALS(ansi_map_AuthorizationDenied_vals), 0,
        "ansi_map.AuthorizationDenied", HFILL }},
    { &hf_ansi_map_authorizationPeriod,
      { "authorizationPeriod", "ansi_map.authorizationPeriod",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.AuthorizationPeriod", HFILL }},
    { &hf_ansi_map_deniedAuthorizationPeriod,
      { "deniedAuthorizationPeriod", "ansi_map.deniedAuthorizationPeriod",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.DeniedAuthorizationPeriod", HFILL }},
    { &hf_ansi_map_randValidTime,
      { "randValidTime", "ansi_map.randValidTime",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.RANDValidTime", HFILL }},
    { &hf_ansi_map_redirectionReason,
      { "redirectionReason", "ansi_map.redirectionReason",
        FT_UINT32, BASE_DEC, VALS(ansi_map_RedirectionReason_vals), 0,
        "ansi_map.RedirectionReason", HFILL }},
    { &hf_ansi_map_cancellationType,
      { "cancellationType", "ansi_map.cancellationType",
        FT_UINT8, BASE_DEC, VALS(ansi_map_CancellationType_vals), 0,
        "ansi_map.CancellationType", HFILL }},
    { &hf_ansi_map_controlChannelData,
      { "controlChannelData", "ansi_map.controlChannelData",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.ControlChannelData", HFILL }},
    { &hf_ansi_map_receivedSignalQuality,
      { "receivedSignalQuality", "ansi_map.receivedSignalQuality",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ansi_map.ReceivedSignalQuality", HFILL }},
    { &hf_ansi_map_systemAccessData,
      { "systemAccessData", "ansi_map.systemAccessData",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.SystemAccessData", HFILL }},
    { &hf_ansi_map_cancellationDenied,
      { "cancellationDenied", "ansi_map.cancellationDenied",
        FT_UINT32, BASE_DEC, VALS(ansi_map_CancellationDenied_vals), 0,
        "ansi_map.CancellationDenied", HFILL }},
    { &hf_ansi_map_availabilityType,
      { "availabilityType", "ansi_map.availabilityType",
        FT_UINT8, BASE_DEC, VALS(ansi_map_AvailabilityType_vals), 0,
        "ansi_map.AvailabilityType", HFILL }},
    { &hf_ansi_map_borderCellAccess,
      { "borderCellAccess", "ansi_map.borderCellAccess",
        FT_UINT32, BASE_DEC, VALS(ansi_map_BorderCellAccess_vals), 0,
        "ansi_map.BorderCellAccess", HFILL }},
    { &hf_ansi_map_msc_Address,
      { "msc-Address", "ansi_map.msc_Address",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.MSC_Address", HFILL }},
    { &hf_ansi_map_sms_Address,
      { "sms-Address", "ansi_map.sms_Address",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.SMS_Address", HFILL }},
    { &hf_ansi_map_digits_Carrier,
      { "digits-Carrier", "ansi_map.digits_Carrier",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.Digits", HFILL }},
    { &hf_ansi_map_authenticationCapability,
      { "authenticationCapability", "ansi_map.authenticationCapability",
        FT_UINT8, BASE_DEC, VALS(ansi_map_AuthenticationCapability_vals), 0,
        "ansi_map.AuthenticationCapability", HFILL }},
    { &hf_ansi_map_callingFeaturesIndicator,
      { "callingFeaturesIndicator", "ansi_map.callingFeaturesIndicator",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.CallingFeaturesIndicator", HFILL }},
    { &hf_ansi_map_geographicAuthorization,
      { "geographicAuthorization", "ansi_map.geographicAuthorization",
        FT_UINT8, BASE_DEC, VALS(ansi_map_GeographicAuthorization_vals), 0,
        "ansi_map.GeographicAuthorization", HFILL }},
    { &hf_ansi_map_originationIndicator,
      { "originationIndicator", "ansi_map.originationIndicator",
        FT_UINT32, BASE_DEC, VALS(ansi_map_OriginationIndicator_vals), 0,
        "ansi_map.OriginationIndicator", HFILL }},
    { &hf_ansi_map_restrictionDigits,
      { "restrictionDigits", "ansi_map.restrictionDigits",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.RestrictionDigits", HFILL }},
    { &hf_ansi_map_sms_OriginationRestrictions,
      { "sms-OriginationRestrictions", "ansi_map.sms_OriginationRestrictions",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.SMS_OriginationRestrictions", HFILL }},
    { &hf_ansi_map_sms_TerminationRestrictions,
      { "sms-TerminationRestrictions", "ansi_map.sms_TerminationRestrictions",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.SMS_TerminationRestrictions", HFILL }},
    { &hf_ansi_map_spinipin,
      { "spinipin", "ansi_map.spinipin",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.SPINIPIN", HFILL }},
    { &hf_ansi_map_spiniTriggers,
      { "spiniTriggers", "ansi_map.spiniTriggers",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.SPINITriggers", HFILL }},
    { &hf_ansi_map_terminationRestrictionCode,
      { "terminationRestrictionCode", "ansi_map.terminationRestrictionCode",
        FT_UINT32, BASE_DEC, VALS(ansi_map_TerminationRestrictionCode_vals), 0,
        "ansi_map.TerminationRestrictionCode", HFILL }},
    { &hf_ansi_map_digitCollectionControl,
      { "digitCollectionControl", "ansi_map.digitCollectionControl",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.DigitCollectionControl", HFILL }},
    { &hf_ansi_map_trunkStatus,
      { "trunkStatus", "ansi_map.trunkStatus",
        FT_UINT32, BASE_DEC, VALS(ansi_map_TrunkStatus_vals), 0,
        "ansi_map.TrunkStatus", HFILL }},
    { &hf_ansi_map_userGroup,
      { "userGroup", "ansi_map.userGroup",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.UserGroup", HFILL }},
    { &hf_ansi_map_voiceMailboxNumber,
      { "voiceMailboxNumber", "ansi_map.voiceMailboxNumber",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.VoiceMailboxNumber", HFILL }},
    { &hf_ansi_map_voiceMailboxPIN,
      { "voiceMailboxPIN", "ansi_map.voiceMailboxPIN",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.VoiceMailboxPIN", HFILL }},
    { &hf_ansi_map_sms_BearerData,
      { "sms-BearerData", "ansi_map.sms_BearerData",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.SMS_BearerData", HFILL }},
    { &hf_ansi_map_sms_TeleserviceIdentifier,
      { "sms-TeleserviceIdentifier", "ansi_map.sms_TeleserviceIdentifier",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.SMS_TeleserviceIdentifier", HFILL }},
    { &hf_ansi_map_sms_ChargeIndicator,
      { "sms-ChargeIndicator", "ansi_map.sms_ChargeIndicator",
        FT_UINT8, BASE_DEC, VALS(ansi_map_SMS_ChargeIndicator_vals), 0,
        "ansi_map.SMS_ChargeIndicator", HFILL }},
    { &hf_ansi_map_sms_DestinationAddress,
      { "sms-DestinationAddress", "ansi_map.sms_DestinationAddress",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.SMS_DestinationAddress", HFILL }},
    { &hf_ansi_map_sms_OriginalDestinationAddress,
      { "sms-OriginalDestinationAddress", "ansi_map.sms_OriginalDestinationAddress",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.SMS_OriginalDestinationAddress", HFILL }},
    { &hf_ansi_map_sms_OriginalDestinationSubaddress,
      { "sms-OriginalDestinationSubaddress", "ansi_map.sms_OriginalDestinationSubaddress",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.SMS_OriginalDestinationSubaddress", HFILL }},
    { &hf_ansi_map_sms_OriginalOriginatingAddress,
      { "sms-OriginalOriginatingAddress", "ansi_map.sms_OriginalOriginatingAddress",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.SMS_OriginalOriginatingAddress", HFILL }},
    { &hf_ansi_map_sms_OriginalOriginatingSubaddress,
      { "sms-OriginalOriginatingSubaddress", "ansi_map.sms_OriginalOriginatingSubaddress",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.SMS_OriginalOriginatingSubaddress", HFILL }},
    { &hf_ansi_map_sms_OriginatingAddress,
      { "sms-OriginatingAddress", "ansi_map.sms_OriginatingAddress",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.SMS_OriginatingAddress", HFILL }},
    { &hf_ansi_map_sms_CauseCode,
      { "sms-CauseCode", "ansi_map.sms_CauseCode",
        FT_UINT8, BASE_DEC, VALS(ansi_map_SMS_CauseCode_vals), 0,
        "ansi_map.SMS_CauseCode", HFILL }},
    { &hf_ansi_map_interMessageTime,
      { "interMessageTime", "ansi_map.interMessageTime",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.InterMessageTime", HFILL }},
    { &hf_ansi_map_newlyAssignedMIN,
      { "newlyAssignedMIN", "ansi_map.newlyAssignedMIN",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.NewlyAssignedMIN", HFILL }},
    { &hf_ansi_map_newlyAssignedIMSI,
      { "newlyAssignedIMSI", "ansi_map.newlyAssignedIMSI",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.NewlyAssignedIMSI", HFILL }},
    { &hf_ansi_map_newMINExtension,
      { "newMINExtension", "ansi_map.newMINExtension",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.NewMINExtension", HFILL }},
    { &hf_ansi_map_sms_MessageCount,
      { "sms-MessageCount", "ansi_map.sms_MessageCount",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.SMS_MessageCount", HFILL }},
    { &hf_ansi_map_sms_NotificationIndicator,
      { "sms-NotificationIndicator", "ansi_map.sms_NotificationIndicator",
        FT_UINT8, BASE_DEC, VALS(ansi_map_SMS_NotificationIndicator_vals), 0,
        "ansi_map.SMS_NotificationIndicator", HFILL }},
    { &hf_ansi_map_temporaryReferenceNumber,
      { "temporaryReferenceNumber", "ansi_map.temporaryReferenceNumber",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.TemporaryReferenceNumber", HFILL }},
    { &hf_ansi_map_mobileStationMSID,
      { "mobileStationMSID", "ansi_map.mobileStationMSID",
        FT_UINT32, BASE_DEC, VALS(ansi_map_MobileStationMSID_vals), 0,
        "ansi_map.MobileStationMSID", HFILL }},
    { &hf_ansi_map_sms_AccessDeniedReason,
      { "sms-AccessDeniedReason", "ansi_map.sms_AccessDeniedReason",
        FT_UINT8, BASE_DEC, VALS(ansi_map_SMS_AccessDeniedReason_vals), 0,
        "ansi_map.SMS_AccessDeniedReason", HFILL }},
    { &hf_ansi_map_seizureType,
      { "seizureType", "ansi_map.seizureType",
        FT_UINT32, BASE_DEC, VALS(ansi_map_SeizureType_vals), 0,
        "ansi_map.SeizureType", HFILL }},
    { &hf_ansi_map_requiredParametersMask,
      { "requiredParametersMask", "ansi_map.requiredParametersMask",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.RequiredParametersMask", HFILL }},
    { &hf_ansi_map_reasonList,
      { "reasonList", "ansi_map.reasonList",
        FT_UINT32, BASE_DEC, VALS(ansi_map_ReasonList_vals), 0,
        "ansi_map.ReasonList", HFILL }},
    { &hf_ansi_map_networkTMSIExpirationTime,
      { "networkTMSIExpirationTime", "ansi_map.networkTMSIExpirationTime",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.NetworkTMSIExpirationTime", HFILL }},
    { &hf_ansi_map_newNetworkTMSI,
      { "newNetworkTMSI", "ansi_map.newNetworkTMSI",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.NewNetworkTMSI", HFILL }},
    { &hf_ansi_map_serviceID,
      { "serviceID", "ansi_map.serviceID",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.ServiceID", HFILL }},
    { &hf_ansi_map_dataAccessElementList,
      { "dataAccessElementList", "ansi_map.dataAccessElementList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ansi_map.DataAccessElementList", HFILL }},
    { &hf_ansi_map_timeDateOffset,
      { "timeDateOffset", "ansi_map.timeDateOffset",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.TimeDateOffset", HFILL }},
    { &hf_ansi_map_timeOfDay,
      { "timeOfDay", "ansi_map.timeOfDay",
        FT_INT32, BASE_DEC, NULL, 0,
        "ansi_map.TimeOfDay", HFILL }},
    { &hf_ansi_map_dmd_BillingIndicator,
      { "dmd-BillingIndicator", "ansi_map.dmd_BillingIndicator",
        FT_UINT32, BASE_DEC, VALS(ansi_map_DMH_BillingIndicator_vals), 0,
        "ansi_map.DMH_BillingIndicator", HFILL }},
    { &hf_ansi_map_failureType,
      { "failureType", "ansi_map.failureType",
        FT_UINT32, BASE_DEC, VALS(ansi_map_FailureType_vals), 0,
        "ansi_map.FailureType", HFILL }},
    { &hf_ansi_map_failureCause,
      { "failureCause", "ansi_map.failureCause",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.FailureCause", HFILL }},
    { &hf_ansi_map_outingDigits,
      { "outingDigits", "ansi_map.outingDigits",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.RoutingDigits", HFILL }},
    { &hf_ansi_map_databaseKey,
      { "databaseKey", "ansi_map.databaseKey",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.DatabaseKey", HFILL }},
    { &hf_ansi_map_modificationRequestList,
      { "modificationRequestList", "ansi_map.modificationRequestList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ansi_map.ModificationRequestList", HFILL }},
    { &hf_ansi_map_modificationResultList,
      { "modificationResultList", "ansi_map.modificationResultList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ansi_map.ModificationResultList", HFILL }},
    { &hf_ansi_map_serviceDataAccessElementList,
      { "serviceDataAccessElementList", "ansi_map.serviceDataAccessElementList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ansi_map.ServiceDataAccessElementList", HFILL }},
    { &hf_ansi_map_privateSpecializedResource,
      { "privateSpecializedResource", "ansi_map.privateSpecializedResource",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.PrivateSpecializedResource", HFILL }},
    { &hf_ansi_map_specializedResource,
      { "specializedResource", "ansi_map.specializedResource",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.SpecializedResource", HFILL }},
    { &hf_ansi_map_executeScript,
      { "executeScript", "ansi_map.executeScript",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.ExecuteScript", HFILL }},
    { &hf_ansi_map_scriptResult,
      { "scriptResult", "ansi_map.scriptResult",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.ScriptResult", HFILL }},
    { &hf_ansi_map_tdmaVoiceMode,
      { "tdmaVoiceMode", "ansi_map.tdmaVoiceMode",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.TDMAVoiceMode", HFILL }},
    { &hf_ansi_map_callStatus,
      { "callStatus", "ansi_map.callStatus",
        FT_UINT32, BASE_DEC, VALS(ansi_map_CallStatus_vals), 0,
        "ansi_map.CallStatus", HFILL }},
    { &hf_ansi_map_releaseCause,
      { "releaseCause", "ansi_map.releaseCause",
        FT_UINT32, BASE_DEC, VALS(ansi_map_ReleaseCause_vals), 0,
        "ansi_map.ReleaseCause", HFILL }},
    { &hf_ansi_map_callRecoveryIDList,
      { "callRecoveryIDList", "ansi_map.callRecoveryIDList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ansi_map.CallRecoveryIDList", HFILL }},
    { &hf_ansi_map_positionInformationCode,
      { "positionInformationCode", "ansi_map.positionInformationCode",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.PositionInformationCode", HFILL }},
    { &hf_ansi_map_mSStatus,
      { "mSStatus", "ansi_map.mSStatus",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.MSStatus", HFILL }},
    { &hf_ansi_map_pSID_RSIDInformation,
      { "pSID-RSIDInformation", "ansi_map.pSID_RSIDInformation",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.PSID_RSIDInformation", HFILL }},
    { &hf_ansi_map_controlType,
      { "controlType", "ansi_map.controlType",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.ControlType", HFILL }},
    { &hf_ansi_map_destinationAddress,
      { "destinationAddress", "ansi_map.destinationAddress",
        FT_UINT32, BASE_DEC, VALS(ansi_map_DestinationAddress_vals), 0,
        "ansi_map.DestinationAddress", HFILL }},
    { &hf_ansi_map_gapDuration,
      { "gapDuration", "ansi_map.gapDuration",
        FT_UINT32, BASE_DEC, VALS(ansi_map_GapDuration_vals), 0,
        "ansi_map.GapDuration", HFILL }},
    { &hf_ansi_map_gapInterval,
      { "gapInterval", "ansi_map.gapInterval",
        FT_UINT32, BASE_DEC, VALS(ansi_map_GapInterval_vals), 0,
        "ansi_map.GapInterval", HFILL }},
    { &hf_ansi_map_invokingNEType,
      { "invokingNEType", "ansi_map.invokingNEType",
        FT_INT32, BASE_DEC, NULL, 0,
        "ansi_map.InvokingNEType", HFILL }},
    { &hf_ansi_map_range,
      { "range", "ansi_map.range",
        FT_INT32, BASE_DEC, NULL, 0,
        "ansi_map.Range", HFILL }},
    { &hf_ansi_map_ctionCode,
      { "ctionCode", "ansi_map.ctionCode",
        FT_UINT8, BASE_DEC, VALS(ansi_map_ActionCode_vals), 0,
        "ansi_map.ActionCode", HFILL }},
    { &hf_ansi_map_aKeyProtocolVersion,
      { "aKeyProtocolVersion", "ansi_map.aKeyProtocolVersion",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.AKeyProtocolVersion", HFILL }},
    { &hf_ansi_map_mobileStationPartialKey,
      { "mobileStationPartialKey", "ansi_map.mobileStationPartialKey",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.MobileStationPartialKey", HFILL }},
    { &hf_ansi_map_newlyAssignedMSID,
      { "newlyAssignedMSID", "ansi_map.newlyAssignedMSID",
        FT_UINT32, BASE_DEC, VALS(ansi_map_NewlyAssignedMSID_vals), 0,
        "ansi_map.NewlyAssignedMSID", HFILL }},
    { &hf_ansi_map_baseStationPartialKey,
      { "baseStationPartialKey", "ansi_map.baseStationPartialKey",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.BaseStationPartialKey", HFILL }},
    { &hf_ansi_map_modulusValue,
      { "modulusValue", "ansi_map.modulusValue",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.ModulusValue", HFILL }},
    { &hf_ansi_map_otasp_ResultCode,
      { "otasp-ResultCode", "ansi_map.otasp_ResultCode",
        FT_UINT8, BASE_DEC, VALS(ansi_map_OTASP_ResultCode_vals), 0,
        "ansi_map.OTASP_ResultCode", HFILL }},
    { &hf_ansi_map_primitiveValue,
      { "primitiveValue", "ansi_map.primitiveValue",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.PrimitiveValue", HFILL }},
    { &hf_ansi_map_announcementCode1,
      { "announcementCode1", "ansi_map.announcementCode1",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.AnnouncementCode", HFILL }},
    { &hf_ansi_map_announcementCode2,
      { "announcementCode2", "ansi_map.announcementCode2",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.AnnouncementCode", HFILL }},
    { &hf_ansi_map_cdmaCodeChannel,
      { "cdmaCodeChannel", "ansi_map.cdmaCodeChannel",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.CDMACodeChannel", HFILL }},
    { &hf_ansi_map_cdmaPilotPN,
      { "cdmaPilotPN", "ansi_map.cdmaPilotPN",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.CDMAPilotPN", HFILL }},
    { &hf_ansi_map_cdmaPowerCombinedIndicator,
      { "cdmaPowerCombinedIndicator", "ansi_map.cdmaPowerCombinedIndicator",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.CDMAPowerCombinedIndicator", HFILL }},
    { &hf_ansi_map_CDMACodeChannelList_item,
      { "Item", "ansi_map.CDMACodeChannelList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.CDMACodeChannelInformation", HFILL }},
    { &hf_ansi_map_cdmaPilotStrength,
      { "cdmaPilotStrength", "ansi_map.cdmaPilotStrength",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.CDMAPilotStrength", HFILL }},
    { &hf_ansi_map_cdmaTargetOneWayDelay,
      { "cdmaTargetOneWayDelay", "ansi_map.cdmaTargetOneWayDelay",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.CDMATargetOneWayDelay", HFILL }},
    { &hf_ansi_map_CDMATargetMAHOList_item,
      { "Item", "ansi_map.CDMATargetMAHOList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.CDMATargetMAHOInformation", HFILL }},
    { &hf_ansi_map_cdmaSignalQuality,
      { "cdmaSignalQuality", "ansi_map.cdmaSignalQuality",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.CDMASignalQuality", HFILL }},
    { &hf_ansi_map_CDMATargetMeasurementList_item,
      { "Item", "ansi_map.CDMATargetMeasurementList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.CDMATargetMeasurementInformation", HFILL }},
    { &hf_ansi_map_TargetMeasurementList_item,
      { "Item", "ansi_map.TargetMeasurementList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.TargetMeasurementInformation", HFILL }},
    { &hf_ansi_map_TerminationList_item,
      { "Item", "ansi_map.TerminationList_item",
        FT_UINT32, BASE_DEC, VALS(ansi_map_TerminationList_item_vals), 0,
        "ansi_map.TerminationList_item", HFILL }},
    { &hf_ansi_map_intersystemTermination,
      { "intersystemTermination", "ansi_map.intersystemTermination",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.IntersystemTermination", HFILL }},
    { &hf_ansi_map_localTermination,
      { "localTermination", "ansi_map.localTermination",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.LocalTermination", HFILL }},
    { &hf_ansi_map_pstnTermination,
      { "pstnTermination", "ansi_map.pstnTermination",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.PSTNTermination", HFILL }},
    { &hf_ansi_map_CDMAServiceOptionList_item,
      { "Item", "ansi_map.CDMAServiceOptionList_item",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.CDMAServiceOption", HFILL }},
    { &hf_ansi_map_pSID_RSIDInformation1,
      { "pSID-RSIDInformation1", "ansi_map.pSID_RSIDInformation1",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.PSID_RSIDInformation", HFILL }},
    { &hf_ansi_map_targetCellID1,
      { "targetCellID1", "ansi_map.targetCellID1",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.TargetCellID", HFILL }},
    { &hf_ansi_map_cdmaConnectionReference,
      { "cdmaConnectionReference", "ansi_map.cdmaConnectionReference",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.CDMAConnectionReference", HFILL }},
    { &hf_ansi_map_cdmaState,
      { "cdmaState", "ansi_map.cdmaState",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.CDMAState", HFILL }},
    { &hf_ansi_map_cdmaServiceOptionConnectionIdentifier,
      { "cdmaServiceOptionConnectionIdentifier", "ansi_map.cdmaServiceOptionConnectionIdentifier",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.CDMAServiceOptionConnectionIdentifier", HFILL }},
    { &hf_ansi_map_CDMAConnectionReferenceList_item,
      { "Item", "ansi_map.CDMAConnectionReferenceList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.CDMAConnectionReferenceList_item", HFILL }},
    { &hf_ansi_map_cdmaConnectionReferenceInformation,
      { "cdmaConnectionReferenceInformation", "ansi_map.cdmaConnectionReferenceInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.CDMAConnectionReferenceInformation", HFILL }},
    { &hf_ansi_map_cdmaConnectionReferenceInformation2,
      { "cdmaConnectionReferenceInformation2", "ansi_map.cdmaConnectionReferenceInformation2",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.CDMAConnectionReferenceInformation", HFILL }},
    { &hf_ansi_map_analogRedirectInfo,
      { "analogRedirectInfo", "ansi_map.analogRedirectInfo",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.AnalogRedirectInfo", HFILL }},
    { &hf_ansi_map_CDMAChannelNumberList_item,
      { "Item", "ansi_map.CDMAChannelNumberList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.CDMAChannelNumberList_item", HFILL }},
    { &hf_ansi_map_cdmaChannelNumber,
      { "cdmaChannelNumber", "ansi_map.cdmaChannelNumber",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.CDMAChannelNumber", HFILL }},
    { &hf_ansi_map_cdmaChannelNumber2,
      { "cdmaChannelNumber2", "ansi_map.cdmaChannelNumber2",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.CDMAChannelNumber", HFILL }},
    { &hf_ansi_map_cdmaChannelNumberList,
      { "cdmaChannelNumberList", "ansi_map.cdmaChannelNumberList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ansi_map.CDMAChannelNumberList", HFILL }},
    { &hf_ansi_map_dataID,
      { "dataID", "ansi_map.dataID",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.DataID", HFILL }},
    { &hf_ansi_map_change,
      { "change", "ansi_map.change",
        FT_UINT32, BASE_DEC, VALS(ansi_map_Change_vals), 0,
        "ansi_map.Change", HFILL }},
    { &hf_ansi_map_dataValue,
      { "dataValue", "ansi_map.dataValue",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.DataValue", HFILL }},
    { &hf_ansi_map_DataAccessElementList_item,
      { "Item", "ansi_map.DataAccessElementList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.DataAccessElementList_item", HFILL }},
    { &hf_ansi_map_dataAccessElement1,
      { "dataAccessElement1", "ansi_map.dataAccessElement1",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.DataAccessElement", HFILL }},
    { &hf_ansi_map_dataAccessElement2,
      { "dataAccessElement2", "ansi_map.dataAccessElement2",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.DataAccessElement", HFILL }},
    { &hf_ansi_map_dataResult,
      { "dataResult", "ansi_map.dataResult",
        FT_UINT32, BASE_DEC, VALS(ansi_map_DataResult_vals), 0,
        "ansi_map.DataResult", HFILL }},
    { &hf_ansi_map_DataUpdateResultList_item,
      { "Item", "ansi_map.DataUpdateResultList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.DataUpdateResult", HFILL }},
    { &hf_ansi_map_globalTitle,
      { "globalTitle", "ansi_map.globalTitle",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.GlobalTitle", HFILL }},
    { &hf_ansi_map_pC_SSN,
      { "pC-SSN", "ansi_map.pC_SSN",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.PC_SSN", HFILL }},
    { &hf_ansi_map_scriptName,
      { "scriptName", "ansi_map.scriptName",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.ScriptName", HFILL }},
    { &hf_ansi_map_scriptArgument,
      { "scriptArgument", "ansi_map.scriptArgument",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.ScriptArgument", HFILL }},
    { &hf_ansi_map_allOrNone,
      { "allOrNone", "ansi_map.allOrNone",
        FT_UINT32, BASE_DEC, VALS(ansi_map_AllOrNone_vals), 0,
        "ansi_map.AllOrNone", HFILL }},
    { &hf_ansi_map_ModificationRequestList_item,
      { "Item", "ansi_map.ModificationRequestList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.ModificationRequest", HFILL }},
    { &hf_ansi_map_serviceDataResultList,
      { "serviceDataResultList", "ansi_map.serviceDataResultList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ansi_map.ServiceDataResultList", HFILL }},
    { &hf_ansi_map_ModificationResultList_item,
      { "Item", "ansi_map.ModificationResultList_item",
        FT_UINT32, BASE_DEC, VALS(ansi_map_ModificationResult_vals), 0,
        "ansi_map.ModificationResult", HFILL }},
    { &hf_ansi_map_ServiceDataAccessElementList_item,
      { "Item", "ansi_map.ServiceDataAccessElementList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.ServiceDataAccessElement", HFILL }},
    { &hf_ansi_map_dataUpdateResultList,
      { "dataUpdateResultList", "ansi_map.dataUpdateResultList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ansi_map.DataUpdateResultList", HFILL }},
    { &hf_ansi_map_ServiceDataResultList_item,
      { "Item", "ansi_map.ServiceDataResultList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.ServiceDataResult", HFILL }},
    { &hf_ansi_map_TriggerAddressList_item,
      { "Item", "ansi_map.TriggerAddressList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.TriggerAddressList_item", HFILL }},
    { &hf_ansi_map_triggerList,
      { "triggerList", "ansi_map.triggerList",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.TriggerList", HFILL }},
    { &hf_ansi_map_triggerListOpt,
      { "triggerListOpt", "ansi_map.triggerListOpt",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.TriggerList", HFILL }},
    { &hf_ansi_map_wIN_TriggerList,
      { "wIN-TriggerList", "ansi_map.wIN_TriggerList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ansi_map.WIN_TriggerList", HFILL }},
    { &hf_ansi_map_triggerCapability,
      { "triggerCapability", "ansi_map.triggerCapability",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.TriggerCapability", HFILL }},
    { &hf_ansi_map_wINOperationsCapability,
      { "wINOperationsCapability", "ansi_map.wINOperationsCapability",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.WINOperationsCapability", HFILL }},
    { &hf_ansi_map_detectionPointType,
      { "detectionPointType", "ansi_map.detectionPointType",
        FT_UINT32, BASE_DEC, VALS(ansi_map_DetectionPointType_vals), 0,
        "ansi_map.DetectionPointType", HFILL }},
    { &hf_ansi_map_WIN_TriggerList_item,
      { "Item", "ansi_map.WIN_TriggerList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.WIN_Trigger", HFILL }},
    { &hf_ansi_map_CallRecoveryIDList_item,
      { "Item", "ansi_map.CallRecoveryIDList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.CallRecoveryID", HFILL }},
    { &hf_ansi_map_sCFOverloadGapInterval,
      { "sCFOverloadGapInterval", "ansi_map.sCFOverloadGapInterval",
        FT_UINT32, BASE_DEC, VALS(ansi_map_SCFOverloadGapInterval_vals), 0,
        "ansi_map.SCFOverloadGapInterval", HFILL }},
    { &hf_ansi_map_serviceManagementSystemGapInterval,
      { "serviceManagementSystemGapInterval", "ansi_map.serviceManagementSystemGapInterval",
        FT_UINT32, BASE_DEC, VALS(ansi_map_ServiceManagementSystemGapInterval_vals), 0,
        "ansi_map.ServiceManagementSystemGapInterval", HFILL }},
    { &hf_ansi_map_mobileStationIMSI,
      { "mobileStationIMSI", "ansi_map.mobileStationIMSI",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ansi_map.MobileStationIMSI", HFILL }},
    { &hf_ansi_map_handoffMeasurementRequest,
      { "handoffMeasurementRequest", "ansi_map.handoffMeasurementRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.HandoffMeasurementRequest", HFILL }},
    { &hf_ansi_map_facilitiesDirective,
      { "facilitiesDirective", "ansi_map.facilitiesDirective",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.FacilitiesDirective", HFILL }},
    { &hf_ansi_map_handoffBack,
      { "handoffBack", "ansi_map.handoffBack",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.HandoffBack", HFILL }},
    { &hf_ansi_map_facilitiesRelease,
      { "facilitiesRelease", "ansi_map.facilitiesRelease",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.FacilitiesRelease", HFILL }},
    { &hf_ansi_map_qualificationRequest,
      { "qualificationRequest", "ansi_map.qualificationRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.QualificationRequest", HFILL }},
    { &hf_ansi_map_qualificationDirective,
      { "qualificationDirective", "ansi_map.qualificationDirective",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.QualificationDirective", HFILL }},
    { &hf_ansi_map_blocking,
      { "blocking", "ansi_map.blocking",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.Blocking", HFILL }},
    { &hf_ansi_map_unblocking,
      { "unblocking", "ansi_map.unblocking",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.Unblocking", HFILL }},
    { &hf_ansi_map_resetCircuit,
      { "resetCircuit", "ansi_map.resetCircuit",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.ResetCircuit", HFILL }},
    { &hf_ansi_map_trunkTest,
      { "trunkTest", "ansi_map.trunkTest",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.TrunkTest", HFILL }},
    { &hf_ansi_map_trunkTestDisconnect,
      { "trunkTestDisconnect", "ansi_map.trunkTestDisconnect",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.TrunkTestDisconnect", HFILL }},
    { &hf_ansi_map_registrationNotification,
      { "registrationNotification", "ansi_map.registrationNotification",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.RegistrationNotification", HFILL }},
    { &hf_ansi_map_registrationCancellation,
      { "registrationCancellation", "ansi_map.registrationCancellation",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.RegistrationCancellation", HFILL }},
    { &hf_ansi_map_locationRequest,
      { "locationRequest", "ansi_map.locationRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.LocationRequest", HFILL }},
    { &hf_ansi_map_routingRequest,
      { "routingRequest", "ansi_map.routingRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.RoutingRequest", HFILL }},
    { &hf_ansi_map_featureRequest,
      { "featureRequest", "ansi_map.featureRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.FeatureRequest", HFILL }},
    { &hf_ansi_map_unreliableRoamerDataDirective,
      { "unreliableRoamerDataDirective", "ansi_map.unreliableRoamerDataDirective",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.UnreliableRoamerDataDirective", HFILL }},
    { &hf_ansi_map_mSInactive,
      { "mSInactive", "ansi_map.mSInactive",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.MSInactive", HFILL }},
    { &hf_ansi_map_transferToNumberRequest,
      { "transferToNumberRequest", "ansi_map.transferToNumberRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.TransferToNumberRequest", HFILL }},
    { &hf_ansi_map_redirectionRequest,
      { "redirectionRequest", "ansi_map.redirectionRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.RedirectionRequest", HFILL }},
    { &hf_ansi_map_handoffToThird,
      { "handoffToThird", "ansi_map.handoffToThird",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.HandoffToThird", HFILL }},
    { &hf_ansi_map_flashRequest,
      { "flashRequest", "ansi_map.flashRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.FlashRequest", HFILL }},
    { &hf_ansi_map_authenticationDirective,
      { "authenticationDirective", "ansi_map.authenticationDirective",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.AuthenticationDirective", HFILL }},
    { &hf_ansi_map_authenticationRequest,
      { "authenticationRequest", "ansi_map.authenticationRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.AuthenticationRequest", HFILL }},
    { &hf_ansi_map_baseStationChallenge,
      { "baseStationChallenge", "ansi_map.baseStationChallenge",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.BaseStationChallenge", HFILL }},
    { &hf_ansi_map_authenticationFailureReport,
      { "authenticationFailureReport", "ansi_map.authenticationFailureReport",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.AuthenticationFailureReport", HFILL }},
    { &hf_ansi_map_countRequest,
      { "countRequest", "ansi_map.countRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.CountRequest", HFILL }},
    { &hf_ansi_map_interSystemPage,
      { "interSystemPage", "ansi_map.interSystemPage",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.InterSystemPage", HFILL }},
    { &hf_ansi_map_unsolicitedResponse,
      { "unsolicitedResponse", "ansi_map.unsolicitedResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.UnsolicitedResponse", HFILL }},
    { &hf_ansi_map_bulkDeregistration,
      { "bulkDeregistration", "ansi_map.bulkDeregistration",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.BulkDeregistration", HFILL }},
    { &hf_ansi_map_handoffMeasurementRequest2,
      { "handoffMeasurementRequest2", "ansi_map.handoffMeasurementRequest2",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.HandoffMeasurementRequest2", HFILL }},
    { &hf_ansi_map_facilitiesDirective2,
      { "facilitiesDirective2", "ansi_map.facilitiesDirective2",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.FacilitiesDirective2", HFILL }},
    { &hf_ansi_map_handoffBack2,
      { "handoffBack2", "ansi_map.handoffBack2",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.HandoffBack2", HFILL }},
    { &hf_ansi_map_handoffToThird2,
      { "handoffToThird2", "ansi_map.handoffToThird2",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.HandoffToThird2", HFILL }},
    { &hf_ansi_map_authenticationDirectiveForward,
      { "authenticationDirectiveForward", "ansi_map.authenticationDirectiveForward",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.AuthenticationDirectiveForward", HFILL }},
    { &hf_ansi_map_authenticationStatusReport,
      { "authenticationStatusReport", "ansi_map.authenticationStatusReport",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.AuthenticationStatusReport", HFILL }},
    { &hf_ansi_map_informationDirective,
      { "informationDirective", "ansi_map.informationDirective",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.InformationDirective", HFILL }},
    { &hf_ansi_map_informationForward,
      { "informationForward", "ansi_map.informationForward",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.InformationForward", HFILL }},
    { &hf_ansi_map_interSystemAnswer,
      { "interSystemAnswer", "ansi_map.interSystemAnswer",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.InterSystemAnswer", HFILL }},
    { &hf_ansi_map_interSystemPage2,
      { "interSystemPage2", "ansi_map.interSystemPage2",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.InterSystemPage2", HFILL }},
    { &hf_ansi_map_interSystemSetup,
      { "interSystemSetup", "ansi_map.interSystemSetup",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.InterSystemSetup", HFILL }},
    { &hf_ansi_map_originationRequest,
      { "originationRequest", "ansi_map.originationRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.OriginationRequest", HFILL }},
    { &hf_ansi_map_randomVariableRequest,
      { "randomVariableRequest", "ansi_map.randomVariableRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.RandomVariableRequest", HFILL }},
    { &hf_ansi_map_redirectionDirective,
      { "redirectionDirective", "ansi_map.redirectionDirective",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.RedirectionDirective", HFILL }},
    { &hf_ansi_map_remoteUserInteractionDirective,
      { "remoteUserInteractionDirective", "ansi_map.remoteUserInteractionDirective",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.RemoteUserInteractionDirective", HFILL }},
    { &hf_ansi_map_sMSDeliveryBackward,
      { "sMSDeliveryBackward", "ansi_map.sMSDeliveryBackward",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.SMSDeliveryBackward", HFILL }},
    { &hf_ansi_map_sMSDeliveryForward,
      { "sMSDeliveryForward", "ansi_map.sMSDeliveryForward",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.SMSDeliveryForward", HFILL }},
    { &hf_ansi_map_sMSDeliveryPointToPoint,
      { "sMSDeliveryPointToPoint", "ansi_map.sMSDeliveryPointToPoint",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.SMSDeliveryPointToPoint", HFILL }},
    { &hf_ansi_map_sMSNotification,
      { "sMSNotification", "ansi_map.sMSNotification",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.SMSNotification", HFILL }},
    { &hf_ansi_map_sMSRequest,
      { "sMSRequest", "ansi_map.sMSRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.SMSRequest", HFILL }},
    { &hf_ansi_map_oTASPRequest,
      { "oTASPRequest", "ansi_map.oTASPRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.OTASPRequest", HFILL }},
    { &hf_ansi_map_changeFacilities,
      { "changeFacilities", "ansi_map.changeFacilities",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.ChangeFacilities", HFILL }},
    { &hf_ansi_map_changeService,
      { "changeService", "ansi_map.changeService",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.ChangeService", HFILL }},
    { &hf_ansi_map_parameterRequest,
      { "parameterRequest", "ansi_map.parameterRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.ParameterRequest", HFILL }},
    { &hf_ansi_map_tMSIDirective,
      { "tMSIDirective", "ansi_map.tMSIDirective",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.TMSIDirective", HFILL }},
    { &hf_ansi_map_serviceRequest,
      { "serviceRequest", "ansi_map.serviceRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.ServiceRequest", HFILL }},
    { &hf_ansi_map_analyzedInformation,
      { "analyzedInformation", "ansi_map.analyzedInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.AnalyzedInformation", HFILL }},
    { &hf_ansi_map_connectionFailureReport,
      { "connectionFailureReport", "ansi_map.connectionFailureReport",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.ConnectionFailureReport", HFILL }},
    { &hf_ansi_map_connectResource,
      { "connectResource", "ansi_map.connectResource",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.ConnectResource", HFILL }},
    { &hf_ansi_map_facilitySelectedAndAvailable,
      { "facilitySelectedAndAvailable", "ansi_map.facilitySelectedAndAvailable",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.FacilitySelectedAndAvailable", HFILL }},
    { &hf_ansi_map_modify,
      { "modify", "ansi_map.modify",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.Modify", HFILL }},
    { &hf_ansi_map_search,
      { "search", "ansi_map.search",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.Search", HFILL }},
    { &hf_ansi_map_seizeResource,
      { "seizeResource", "ansi_map.seizeResource",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.SeizeResource", HFILL }},
    { &hf_ansi_map_sRFDirective,
      { "sRFDirective", "ansi_map.sRFDirective",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.SRFDirective", HFILL }},
    { &hf_ansi_map_tBusy,
      { "tBusy", "ansi_map.tBusy",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.TBusy", HFILL }},
    { &hf_ansi_map_tNoAnswer,
      { "tNoAnswer", "ansi_map.tNoAnswer",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.TNoAnswer", HFILL }},
    { &hf_ansi_map_messageDirective,
      { "messageDirective", "ansi_map.messageDirective",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.MessageDirective", HFILL }},
    { &hf_ansi_map_bulkDisconnection,
      { "bulkDisconnection", "ansi_map.bulkDisconnection",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.BulkDisconnection", HFILL }},
    { &hf_ansi_map_callControlDirective,
      { "callControlDirective", "ansi_map.callControlDirective",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.CallControlDirective", HFILL }},
    { &hf_ansi_map_oAnswer,
      { "oAnswer", "ansi_map.oAnswer",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.OAnswer", HFILL }},
    { &hf_ansi_map_oDisconnect,
      { "oDisconnect", "ansi_map.oDisconnect",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.ODisconnect", HFILL }},
    { &hf_ansi_map_callRecoveryReport,
      { "callRecoveryReport", "ansi_map.callRecoveryReport",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.CallRecoveryReport", HFILL }},
    { &hf_ansi_map_tAnswer,
      { "tAnswer", "ansi_map.tAnswer",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.TAnswer", HFILL }},
    { &hf_ansi_map_tDisconnect,
      { "tDisconnect", "ansi_map.tDisconnect",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.TDisconnect", HFILL }},
    { &hf_ansi_map_unreliableCallData,
      { "unreliableCallData", "ansi_map.unreliableCallData",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.UnreliableCallData", HFILL }},
    { &hf_ansi_map_oCalledPartyBusy,
      { "oCalledPartyBusy", "ansi_map.oCalledPartyBusy",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.OCalledPartyBusy", HFILL }},
    { &hf_ansi_map_oNoAnswer,
      { "oNoAnswer", "ansi_map.oNoAnswer",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.ONoAnswer", HFILL }},
    { &hf_ansi_map_positionRequest,
      { "positionRequest", "ansi_map.positionRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.PositionRequest", HFILL }},
    { &hf_ansi_map_positionRequestForward,
      { "positionRequestForward", "ansi_map.positionRequestForward",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.PositionRequestForward", HFILL }},
    { &hf_ansi_map_aCGDirective,
      { "aCGDirective", "ansi_map.aCGDirective",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.ACGDirective", HFILL }},
    { &hf_ansi_map_roamerDatabaseVerificationRequest,
      { "roamerDatabaseVerificationRequest", "ansi_map.roamerDatabaseVerificationRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.RoamerDatabaseVerificationRequest", HFILL }},
    { &hf_ansi_map_addService,
      { "addService", "ansi_map.addService",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.AddService", HFILL }},
    { &hf_ansi_map_dropService,
      { "dropService", "ansi_map.dropService",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.DropService", HFILL }},
    { &hf_ansi_map_handoffMeasurementRequestRes,
      { "handoffMeasurementRequestRes", "ansi_map.handoffMeasurementRequestRes",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.HandoffMeasurementRequestRes", HFILL }},
    { &hf_ansi_map_facilitiesDirectiveRes,
      { "facilitiesDirectiveRes", "ansi_map.facilitiesDirectiveRes",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.FacilitiesDirectiveRes", HFILL }},
    { &hf_ansi_map_handoffBackRes,
      { "handoffBackRes", "ansi_map.handoffBackRes",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.HandoffBackRes", HFILL }},
    { &hf_ansi_map_facilitiesReleaseRes,
      { "facilitiesReleaseRes", "ansi_map.facilitiesReleaseRes",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.FacilitiesReleaseRes", HFILL }},
    { &hf_ansi_map_qualificationRequestRes,
      { "qualificationRequestRes", "ansi_map.qualificationRequestRes",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.QualificationRequestRes", HFILL }},
    { &hf_ansi_map_resetCircuitRes,
      { "resetCircuitRes", "ansi_map.resetCircuitRes",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.ResetCircuitRes", HFILL }},
    { &hf_ansi_map_registrationNotificationRes,
      { "registrationNotificationRes", "ansi_map.registrationNotificationRes",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.RegistrationNotificationRes", HFILL }},
    { &hf_ansi_map_registrationCancellationRes,
      { "registrationCancellationRes", "ansi_map.registrationCancellationRes",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.RegistrationCancellationRes", HFILL }},
    { &hf_ansi_map_locationRequestRes,
      { "locationRequestRes", "ansi_map.locationRequestRes",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.LocationRequestRes", HFILL }},
    { &hf_ansi_map_routingRequestRes,
      { "routingRequestRes", "ansi_map.routingRequestRes",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.RoutingRequestRes", HFILL }},
    { &hf_ansi_map_featureRequestRes,
      { "featureRequestRes", "ansi_map.featureRequestRes",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.FeatureRequestRes", HFILL }},
    { &hf_ansi_map_transferToNumberRequestRes,
      { "transferToNumberRequestRes", "ansi_map.transferToNumberRequestRes",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.TransferToNumberRequestRes", HFILL }},
    { &hf_ansi_map_handoffToThirdRes,
      { "handoffToThirdRes", "ansi_map.handoffToThirdRes",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.HandoffToThirdRes", HFILL }},
    { &hf_ansi_map_authenticationDirectiveRes,
      { "authenticationDirectiveRes", "ansi_map.authenticationDirectiveRes",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.AuthenticationDirectiveRes", HFILL }},
    { &hf_ansi_map_authenticationRequestRes,
      { "authenticationRequestRes", "ansi_map.authenticationRequestRes",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.AuthenticationRequestRes", HFILL }},
    { &hf_ansi_map_authenticationFailureReportRes,
      { "authenticationFailureReportRes", "ansi_map.authenticationFailureReportRes",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.AuthenticationFailureReportRes", HFILL }},
    { &hf_ansi_map_countRequestRes,
      { "countRequestRes", "ansi_map.countRequestRes",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.CountRequestRes", HFILL }},
    { &hf_ansi_map_interSystemPageRes,
      { "interSystemPageRes", "ansi_map.interSystemPageRes",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.InterSystemPageRes", HFILL }},
    { &hf_ansi_map_unsolicitedResponseRes,
      { "unsolicitedResponseRes", "ansi_map.unsolicitedResponseRes",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.UnsolicitedResponseRes", HFILL }},
    { &hf_ansi_map_handoffMeasurementRequest2Res,
      { "handoffMeasurementRequest2Res", "ansi_map.handoffMeasurementRequest2Res",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.HandoffMeasurementRequest2Res", HFILL }},
    { &hf_ansi_map_facilitiesDirective2Res,
      { "facilitiesDirective2Res", "ansi_map.facilitiesDirective2Res",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.FacilitiesDirective2Res", HFILL }},
    { &hf_ansi_map_handoffBack2Res,
      { "handoffBack2Res", "ansi_map.handoffBack2Res",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.HandoffBack2Res", HFILL }},
    { &hf_ansi_map_handoffToThird2Res,
      { "handoffToThird2Res", "ansi_map.handoffToThird2Res",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.HandoffToThird2Res", HFILL }},
    { &hf_ansi_map_authenticationDirectiveForwardRes,
      { "authenticationDirectiveForwardRes", "ansi_map.authenticationDirectiveForwardRes",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.AuthenticationDirectiveForwardRes", HFILL }},
    { &hf_ansi_map_authenticationStatusReportRes,
      { "authenticationStatusReportRes", "ansi_map.authenticationStatusReportRes",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.AuthenticationStatusReportRes", HFILL }},
    { &hf_ansi_map_informationForwardRes,
      { "informationForwardRes", "ansi_map.informationForwardRes",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.InformationForwardRes", HFILL }},
    { &hf_ansi_map_interSystemPage2Res,
      { "interSystemPage2Res", "ansi_map.interSystemPage2Res",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.InterSystemPage2Res", HFILL }},
    { &hf_ansi_map_interSystemSetupRes,
      { "interSystemSetupRes", "ansi_map.interSystemSetupRes",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.InterSystemSetupRes", HFILL }},
    { &hf_ansi_map_originationRequestRes,
      { "originationRequestRes", "ansi_map.originationRequestRes",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.OriginationRequestRes", HFILL }},
    { &hf_ansi_map_randomVariableRequestRes,
      { "randomVariableRequestRes", "ansi_map.randomVariableRequestRes",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.RandomVariableRequestRes", HFILL }},
    { &hf_ansi_map_remoteUserInteractionDirectiveRes,
      { "remoteUserInteractionDirectiveRes", "ansi_map.remoteUserInteractionDirectiveRes",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.RemoteUserInteractionDirectiveRes", HFILL }},
    { &hf_ansi_map_sMSDeliveryBackwardRes,
      { "sMSDeliveryBackwardRes", "ansi_map.sMSDeliveryBackwardRes",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.SMSDeliveryBackwardRes", HFILL }},
    { &hf_ansi_map_sMSDeliveryForwardRes,
      { "sMSDeliveryForwardRes", "ansi_map.sMSDeliveryForwardRes",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.SMSDeliveryForwardRes", HFILL }},
    { &hf_ansi_map_sMSDeliveryPointToPointRes,
      { "sMSDeliveryPointToPointRes", "ansi_map.sMSDeliveryPointToPointRes",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.SMSDeliveryPointToPointRes", HFILL }},
    { &hf_ansi_map_sMSNotificationRes,
      { "sMSNotificationRes", "ansi_map.sMSNotificationRes",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.SMSNotificationRes", HFILL }},
    { &hf_ansi_map_sMSRequestRes,
      { "sMSRequestRes", "ansi_map.sMSRequestRes",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.SMSRequestRes", HFILL }},
    { &hf_ansi_map_oTASPRequestRes,
      { "oTASPRequestRes", "ansi_map.oTASPRequestRes",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.OTASPRequestRes", HFILL }},
    { &hf_ansi_map_changeFacilitiesRes,
      { "changeFacilitiesRes", "ansi_map.changeFacilitiesRes",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.ChangeFacilitiesRes", HFILL }},
    { &hf_ansi_map_changeServiceRes,
      { "changeServiceRes", "ansi_map.changeServiceRes",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.ChangeServiceRes", HFILL }},
    { &hf_ansi_map_parameterRequestRes,
      { "parameterRequestRes", "ansi_map.parameterRequestRes",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.ParameterRequestRes", HFILL }},
    { &hf_ansi_map_tMSIDirectiveRes,
      { "tMSIDirectiveRes", "ansi_map.tMSIDirectiveRes",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.TMSIDirectiveRes", HFILL }},
    { &hf_ansi_map_serviceRequestRes,
      { "serviceRequestRes", "ansi_map.serviceRequestRes",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.ServiceRequestRes", HFILL }},
    { &hf_ansi_map_analyzedInformationRes,
      { "analyzedInformationRes", "ansi_map.analyzedInformationRes",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.AnalyzedInformationRes", HFILL }},
    { &hf_ansi_map_facilitySelectedAndAvailableRes,
      { "facilitySelectedAndAvailableRes", "ansi_map.facilitySelectedAndAvailableRes",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.FacilitySelectedAndAvailableRes", HFILL }},
    { &hf_ansi_map_modifyRes,
      { "modifyRes", "ansi_map.modifyRes",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.ModifyRes", HFILL }},
    { &hf_ansi_map_searchRes,
      { "searchRes", "ansi_map.searchRes",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.SearchRes", HFILL }},
    { &hf_ansi_map_seizeResourceRes,
      { "seizeResourceRes", "ansi_map.seizeResourceRes",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.SeizeResourceRes", HFILL }},
    { &hf_ansi_map_sRFDirectiveRes,
      { "sRFDirectiveRes", "ansi_map.sRFDirectiveRes",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.SRFDirectiveRes", HFILL }},
    { &hf_ansi_map_tBusyRes,
      { "tBusyRes", "ansi_map.tBusyRes",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.TBusyRes", HFILL }},
    { &hf_ansi_map_tNoAnswerRes,
      { "tNoAnswerRes", "ansi_map.tNoAnswerRes",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.TNoAnswerRes", HFILL }},
    { &hf_ansi_map_callControlDirectiveRes,
      { "callControlDirectiveRes", "ansi_map.callControlDirectiveRes",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.CallControlDirectiveRes", HFILL }},
    { &hf_ansi_map_oDisconnectRes,
      { "oDisconnectRes", "ansi_map.oDisconnectRes",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.ODisconnectRes", HFILL }},
    { &hf_ansi_map_tDisconnectRes,
      { "tDisconnectRes", "ansi_map.tDisconnectRes",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.TDisconnectRes", HFILL }},
    { &hf_ansi_map_oCalledPartyBusyRes,
      { "oCalledPartyBusyRes", "ansi_map.oCalledPartyBusyRes",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.OCalledPartyBusyRes", HFILL }},
    { &hf_ansi_map_oNoAnswerRes,
      { "oNoAnswerRes", "ansi_map.oNoAnswerRes",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.ONoAnswerRes", HFILL }},
    { &hf_ansi_map_positionRequestRes,
      { "positionRequestRes", "ansi_map.positionRequestRes",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.PositionRequestRes", HFILL }},
    { &hf_ansi_map_positionRequestForwardRes,
      { "positionRequestForwardRes", "ansi_map.positionRequestForwardRes",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.PositionRequestForwardRes", HFILL }},
    { &hf_ansi_map_roamerDatabaseVerificationRequestRes,
      { "roamerDatabaseVerificationRequestRes", "ansi_map.roamerDatabaseVerificationRequestRes",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.RoamerDatabaseVerificationRequestRes", HFILL }},
    { &hf_ansi_map_addServiceRes,
      { "addServiceRes", "ansi_map.addServiceRes",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.AddServiceRes", HFILL }},
    { &hf_ansi_map_dropServiceRes,
      { "dropServiceRes", "ansi_map.dropServiceRes",
        FT_NONE, BASE_NONE, NULL, 0,
        "ansi_map.DropServiceRes", HFILL }},

/*--- End of included file: packet-ansi_map-hfarr.c ---*/
#line 4801 "packet-ansi_map-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
	  &ett_ansi_map,
	  &ett_mintype,
	  &ett_digitstype,
	  &ett_billingid,
	  &ett_sms_bearer_data,
	  &ett_sms_teleserviceIdentifier,
	  &ett_extendedmscid,
	  &ett_extendedsystemmytypecode,
	  &ett_handoffstate,
	  &ett_mscid,
	  &ett_cdmachanneldata,
	  &ett_cdmastationclassmark,
	  &ett_channeldata,
	  &ett_confidentialitymodes,
	  &ett_CDMA2000HandoffInvokeIOSData,
	  &ett_CDMA2000HandoffResponseIOSData,
	  &ett_originationtriggers,
	  &ett_pacaindicator,
	  &ett_callingpartyname,
	  &ett_triggercapability,
	  &ett_winoperationscapability,
	  &ett_controlnetworkid,
	  &ett_transactioncapability,
	  &ett_cdmaserviceoption,
	  &ett_systemcapabilities,

/*--- Included file: packet-ansi_map-ettarr.c ---*/
#line 1 "packet-ansi_map-ettarr.c"
    &ett_ansi_map_ComponentPDU,
    &ett_ansi_map_InvokePDU,
    &ett_ansi_map_ReturnResultPDU,
    &ett_ansi_map_ReturnErrorPDU,
    &ett_ansi_map_RejectPDU,
    &ett_ansi_map_OperationCode,
    &ett_ansi_map_ErrorCode,
    &ett_ansi_map_AuthenticationDirective,
    &ett_ansi_map_AuthenticationDirectiveRes,
    &ett_ansi_map_AuthenticationDirectiveForward,
    &ett_ansi_map_AuthenticationDirectiveForwardRes,
    &ett_ansi_map_AuthenticationFailureReport,
    &ett_ansi_map_AuthenticationFailureReportRes,
    &ett_ansi_map_AuthenticationRequest,
    &ett_ansi_map_AuthenticationRequestRes,
    &ett_ansi_map_AuthenticationStatusReport,
    &ett_ansi_map_AuthenticationStatusReportRes,
    &ett_ansi_map_BaseStationChallenge,
    &ett_ansi_map_BaseStationChallengeRes,
    &ett_ansi_map_Blocking,
    &ett_ansi_map_BulkDeregistration,
    &ett_ansi_map_CountRequest,
    &ett_ansi_map_CountRequestRes,
    &ett_ansi_map_FacilitiesDirective,
    &ett_ansi_map_FacilitiesDirectiveRes,
    &ett_ansi_map_FacilitiesDirective2,
    &ett_ansi_map_FacilitiesDirective2Res,
    &ett_ansi_map_FacilitiesRelease,
    &ett_ansi_map_FacilitiesReleaseRes,
    &ett_ansi_map_FeatureRequest,
    &ett_ansi_map_FeatureRequestRes,
    &ett_ansi_map_FlashRequest,
    &ett_ansi_map_HandoffBack,
    &ett_ansi_map_HandoffBackRes,
    &ett_ansi_map_HandoffBack2,
    &ett_ansi_map_HandoffBack2Res,
    &ett_ansi_map_HandoffMeasurementRequest,
    &ett_ansi_map_HandoffMeasurementRequestRes,
    &ett_ansi_map_HandoffMeasurementRequest2,
    &ett_ansi_map_HandoffMeasurementRequest2Res,
    &ett_ansi_map_HandoffToThird,
    &ett_ansi_map_HandoffToThirdRes,
    &ett_ansi_map_HandoffToThird2,
    &ett_ansi_map_HandoffToThird2Res,
    &ett_ansi_map_InformationDirective,
    &ett_ansi_map_InformationDirectiveRes,
    &ett_ansi_map_InformationForward,
    &ett_ansi_map_InformationForwardRes,
    &ett_ansi_map_InterSystemAnswer,
    &ett_ansi_map_InterSystemPage,
    &ett_ansi_map_InterSystemPageRes,
    &ett_ansi_map_InterSystemPage2,
    &ett_ansi_map_InterSystemPage2Res,
    &ett_ansi_map_InterSystemSetup,
    &ett_ansi_map_InterSystemSetupRes,
    &ett_ansi_map_LocationRequest,
    &ett_ansi_map_LocationRequestRes,
    &ett_ansi_map_MSInactive,
    &ett_ansi_map_OriginationRequest,
    &ett_ansi_map_OriginationRequestRes,
    &ett_ansi_map_QualificationDirective,
    &ett_ansi_map_QualificationRequest,
    &ett_ansi_map_QualificationRequestRes,
    &ett_ansi_map_RandomVariableRequest,
    &ett_ansi_map_RandomVariableRequestRes,
    &ett_ansi_map_RedirectionDirective,
    &ett_ansi_map_RedirectionRequest,
    &ett_ansi_map_RegistrationCancellation,
    &ett_ansi_map_RegistrationCancellationRes,
    &ett_ansi_map_RegistrationNotification,
    &ett_ansi_map_RegistrationNotificationRes,
    &ett_ansi_map_RemoteUserInteractionDirective,
    &ett_ansi_map_RemoteUserInteractionDirectiveRes,
    &ett_ansi_map_ResetCircuit,
    &ett_ansi_map_ResetCircuitRes,
    &ett_ansi_map_RoutingRequest,
    &ett_ansi_map_RoutingRequestRes,
    &ett_ansi_map_SMSDeliveryBackward,
    &ett_ansi_map_SMSDeliveryBackwardRes,
    &ett_ansi_map_SMSDeliveryForward,
    &ett_ansi_map_SMSDeliveryForwardRes,
    &ett_ansi_map_SMSDeliveryPointToPoint,
    &ett_ansi_map_SMSDeliveryPointToPointRes,
    &ett_ansi_map_SMSNotification,
    &ett_ansi_map_SMSNotificationRes,
    &ett_ansi_map_SMSRequest,
    &ett_ansi_map_SMSRequestRes,
    &ett_ansi_map_TransferToNumberRequest,
    &ett_ansi_map_TransferToNumberRequestRes,
    &ett_ansi_map_TrunkTest,
    &ett_ansi_map_TrunkTestDisconnect,
    &ett_ansi_map_Unblocking,
    &ett_ansi_map_UnreliableRoamerDataDirective,
    &ett_ansi_map_UnsolicitedResponse,
    &ett_ansi_map_UnsolicitedResponseRes,
    &ett_ansi_map_ParameterRequest,
    &ett_ansi_map_ParameterRequestRes,
    &ett_ansi_map_TMSIDirective,
    &ett_ansi_map_TMSIDirectiveRes,
    &ett_ansi_map_NumberPortabilityRequest,
    &ett_ansi_map_ServiceRequest,
    &ett_ansi_map_ServiceRequestRes,
    &ett_ansi_map_AnalyzedInformation,
    &ett_ansi_map_AnalyzedInformationRes,
    &ett_ansi_map_ConnectionFailureReport,
    &ett_ansi_map_ConnectResource,
    &ett_ansi_map_FacilitySelectedAndAvailable,
    &ett_ansi_map_FacilitySelectedAndAvailableRes,
    &ett_ansi_map_Modify,
    &ett_ansi_map_ModifyRes,
    &ett_ansi_map_Search,
    &ett_ansi_map_SearchRes,
    &ett_ansi_map_SeizeResource,
    &ett_ansi_map_SeizeResourceRes,
    &ett_ansi_map_SRFDirective,
    &ett_ansi_map_SRFDirectiveRes,
    &ett_ansi_map_TBusy,
    &ett_ansi_map_TBusyRes,
    &ett_ansi_map_TNoAnswer,
    &ett_ansi_map_TNoAnswerRes,
    &ett_ansi_map_ChangeFacilities,
    &ett_ansi_map_ChangeFacilitiesRes,
    &ett_ansi_map_ChangeService,
    &ett_ansi_map_ChangeServiceRes,
    &ett_ansi_map_MessageDirective,
    &ett_ansi_map_BulkDisconnection,
    &ett_ansi_map_CallControlDirective,
    &ett_ansi_map_CallControlDirectiveRes,
    &ett_ansi_map_OAnswer,
    &ett_ansi_map_ODisconnect,
    &ett_ansi_map_ODisconnectRes,
    &ett_ansi_map_CallRecoveryReport,
    &ett_ansi_map_TAnswer,
    &ett_ansi_map_TDisconnect,
    &ett_ansi_map_TDisconnectRes,
    &ett_ansi_map_UnreliableCallData,
    &ett_ansi_map_OCalledPartyBusy,
    &ett_ansi_map_OCalledPartyBusyRes,
    &ett_ansi_map_ONoAnswer,
    &ett_ansi_map_ONoAnswerRes,
    &ett_ansi_map_PositionRequest,
    &ett_ansi_map_PositionRequestRes,
    &ett_ansi_map_PositionRequestForward,
    &ett_ansi_map_PositionRequestForwardRes,
    &ett_ansi_map_ACGDirective,
    &ett_ansi_map_RoamerDatabaseVerificationRequest,
    &ett_ansi_map_RoamerDatabaseVerificationRequestRes,
    &ett_ansi_map_AddService,
    &ett_ansi_map_AddServiceRes,
    &ett_ansi_map_DropService,
    &ett_ansi_map_DropServiceRes,
    &ett_ansi_map_OTASPRequest,
    &ett_ansi_map_OTASPRequestRes,
    &ett_ansi_map_AnnouncementList,
    &ett_ansi_map_CDMACodeChannelInformation,
    &ett_ansi_map_CDMACodeChannelList,
    &ett_ansi_map_CDMATargetMAHOInformation,
    &ett_ansi_map_CDMATargetMAHOList,
    &ett_ansi_map_CDMATargetMeasurementInformation,
    &ett_ansi_map_CDMATargetMeasurementList,
    &ett_ansi_map_IntersystemTermination,
    &ett_ansi_map_LocalTermination,
    &ett_ansi_map_Profile,
    &ett_ansi_map_PSTNTermination,
    &ett_ansi_map_TargetMeasurementInformation,
    &ett_ansi_map_TargetMeasurementList,
    &ett_ansi_map_TerminationList,
    &ett_ansi_map_TerminationList_item,
    &ett_ansi_map_CDMAServiceOptionList,
    &ett_ansi_map_PSID_RSIDList,
    &ett_ansi_map_TargetCellIDList,
    &ett_ansi_map_CDMAConnectionReferenceInformation,
    &ett_ansi_map_CDMAConnectionReferenceList,
    &ett_ansi_map_CDMAConnectionReferenceList_item,
    &ett_ansi_map_AnalogRedirectRecord,
    &ett_ansi_map_CDMAChannelNumberList,
    &ett_ansi_map_CDMAChannelNumberList_item,
    &ett_ansi_map_CDMARedirectRecord,
    &ett_ansi_map_MSID,
    &ett_ansi_map_DataAccessElement,
    &ett_ansi_map_DataAccessElementList,
    &ett_ansi_map_DataAccessElementList_item,
    &ett_ansi_map_DataUpdateResult,
    &ett_ansi_map_DataUpdateResultList,
    &ett_ansi_map_DestinationAddress,
    &ett_ansi_map_ExecuteScript,
    &ett_ansi_map_ModificationRequest,
    &ett_ansi_map_ModificationRequestList,
    &ett_ansi_map_ModificationResult,
    &ett_ansi_map_ModificationResultList,
    &ett_ansi_map_ServiceDataAccessElement,
    &ett_ansi_map_ServiceDataAccessElementList,
    &ett_ansi_map_ServiceDataResult,
    &ett_ansi_map_ServiceDataResultList,
    &ett_ansi_map_SRFCapability,
    &ett_ansi_map_TriggerAddressList,
    &ett_ansi_map_TriggerAddressList_item,
    &ett_ansi_map_TriggerList,
    &ett_ansi_map_WINCapability,
    &ett_ansi_map_WIN_Trigger,
    &ett_ansi_map_WIN_TriggerList,
    &ett_ansi_map_CallRecoveryID,
    &ett_ansi_map_CallRecoveryIDList,
    &ett_ansi_map_GapInterval,
    &ett_ansi_map_MobileStationMSID,
    &ett_ansi_map_NewlyAssignedMSID,
    &ett_ansi_map_InvokeData,
    &ett_ansi_map_ReturnData,

/*--- End of included file: packet-ansi_map-ettarr.c ---*/
#line 4831 "packet-ansi_map-template.c"
  };


  /* Register protocol */
  proto_ansi_map = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_ansi_map, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

 
  register_dissector("ansi_map", dissect_ansi_map, proto_ansi_map);

  is637_tele_id_dissector_table =
	  register_dissector_table("ansi_map.tele_id", "IS-637 Teleservice ID",
	    FT_UINT8, BASE_DEC);

  is683_dissector_table =
	register_dissector_table("ansi_map.ota", "IS-683-A (OTA)",
	    FT_UINT8, BASE_DEC);

  is801_dissector_table =
	register_dissector_table("ansi_map.pld", "IS-801 (PLD)",
	    FT_UINT8, BASE_DEC);

  ansi_map_tap = register_tap("ansi_map");


  range_convert_str(&global_ssn_range, "5-14", MAX_SSN);

  ssn_range = range_empty();

  ansi_map_module = prefs_register_protocol(proto_ansi_map, proto_reg_handoff_ansi_map);
    

  prefs_register_range_preference(ansi_map_module, "map.ssn", "ANSI MAP SSNs",
				    "ANSI MAP SSNs to decode as ANSI MAP",
				    &global_ssn_range, MAX_SSN);

  register_init_routine(&ansi_map_init_protocol);
}





