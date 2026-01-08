/* packet-json_3gpp.c
 * Routines for JSON dissection - 3GPP Extension
 *
 * References:
 * - 3GPP TS 24.301
 * - 3GPP TS 24.501
 * - 3GPP TS 29.274
 * - 3GPP TS 29.500
 * - 3GPP TS 29.502
 * - 3GPP TS 29.503
 * - 3GPP TS 29.507
 * - 3GPP TS 29.512
 * - 3GPP TS 29.517
 *   3GPP TS 29.525
 * - 3GPP TS 29.571
 * - 3GPP TS 29.572
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* This dissector registers a dissector table for 3GPP Vendor specific
 * keys which will be called from the JSON dissector to dissect
 * the content of keys of the OctetString type(or similar).
 */

#include "config.h"

#include <epan/etypes.h>
#include <epan/expert.h>
#include <epan/packet.h>
#include <epan/tvbparse.h>
#include <epan/proto_data.h>

#include "packet-e212.h"
#include "packet-gtpv2.h"
#include "packet-gsm_a_common.h"
#include "packet-json.h"
#include "packet-http.h"
#include "packet-http2.h"

void proto_register_json_3gpp(void);
void proto_reg_handoff_json_3gpp(void);

static int proto_json_3gpp;
static int proto_http;

static int ett_json_base64decoded_eps_ie;
static int ett_json_base64decoded_nas5g_ie;
static int ett_json_3gpp_data;

static expert_field ei_json_3gpp_data_not_decoded;
static expert_field ei_json_3gpp_encoding_error;

static int hf_json_3gpp_binary_data;

static int hf_json_3gpp_ueepspdnconnection;
static int hf_json_3gpp_bearerlevelqos;
static int hf_json_3gpp_epsbearersetup;
static int hf_json_3gpp_forwardingbearercontexts;
static int hf_json_3gpp_forwardingfteid;
static int hf_json_3gpp_pgwnodename;
static int hf_json_3gpp_pgws8cfteid;
static int hf_json_3gpp_pgws8ufteid;
static int hf_json_3gpp_qosrules;
static int hf_json_3gpp_qosflowdescription;
static int hf_json_3gpp_suppFeat;
static int hf_json_3gpp_supportedFeatures;
static int hf_json_3gpp_supi;
static int hf_json_3gpp_subscriberIdentifier;
static int hf_json_3gpp_notifyuri;
static int hf_json_3gpp_notificationuri;
static int hf_json_3gpp_amfStatusUri;
static int hf_json_3gpp_n1NotifyCallbackUri;
static int hf_json_3gpp_n2NotifyCallbackUri;
static int hf_json_3gpp_n1n2FailureTxfNotifURI;
static int hf_json_3gpp_ismfPduSessionUri;
static int hf_json_3gpp_hsmfPduSessionUri;
static int hf_json_3gpp_vsmfPduSessionUri;
static int hf_json_3gpp_callbackReference;
static int hf_json_3gpp_pcscfRestorationCallbackUri;
static int hf_json_3gpp_deregCallbackUri;
static int hf_json_3gpp_staleCheckCallbackUri;


static int hf_json_3gpp_suppfeat;

static int hf_json_3gpp_suppfeat_naf_eventexposure_1_serviceexperience;
static int hf_json_3gpp_suppfeat_naf_eventexposure_2_uemobility;
static int hf_json_3gpp_suppfeat_naf_eventexposure_3_uecommunication;
static int hf_json_3gpp_suppfeat_naf_eventexposure_4_exceptions;

static int hf_json_3gpp_suppfeat_naf_eventexposure_5_es3xx;
static int hf_json_3gpp_suppfeat_naf_eventexposure_6_enena;
static int hf_json_3gpp_suppfeat_naf_eventexposure_7_userdatacongestion;
static int hf_json_3gpp_suppfeat_naf_eventexposure_8_performancedata;

static int hf_json_3gpp_suppfeat_naf_eventexposure_9_dispersion;
static int hf_json_3gpp_suppfeat_naf_eventexposure_10_collectivebehaviour;
static int hf_json_3gpp_suppfeat_naf_eventexposure_11_serviceexperienceext;
static int hf_json_3gpp_suppfeat_naf_eventexposure_12_msqoemetrics;

static int hf_json_3gpp_suppfeat_naf_eventexposure_13_msconsumption;
static int hf_json_3gpp_suppfeat_naf_eventexposure_14_msnetassinvocation;
static int hf_json_3gpp_suppfeat_naf_eventexposure_15_msdynpolicyinvocation;
static int hf_json_3gpp_suppfeat_naf_eventexposure_16_msaccessactivity;

static int hf_json_3gpp_suppfeat_naf_eventexposure_17_dataaccprofileid;
static int hf_json_3gpp_suppfeat_naf_eventexposure_18_allapplications;
static int hf_json_3gpp_suppfeat_naf_eventexposure_19_gnssassistdata;
static int hf_json_3gpp_suppfeat_naf_eventexposure_20_performancedataext_aiml;

static int hf_json_3gpp_suppfeat_naf_eventexposure_21_uemobilityext_aiml;
static int hf_json_3gpp_suppfeat_naf_eventexposure_22_enperformancedata;
static int hf_json_3gpp_suppfeat_naf_eventexposure_23_uecommunicationext_ena;
static int hf_json_3gpp_suppfeat_naf_eventexposure_24_serviceexperienceext2_ena;

static int hf_json_3gpp_suppfeat_naf_eventexposure_25_enhdatamgmt;
static int hf_json_3gpp_suppfeat_naf_eventexposure_26_exteventfilters;
static int hf_json_3gpp_suppfeat_naf_eventexposure_27_datavoltransfertime;
static int hf_json_3gpp_suppfeat_naf_eventexposure_28_mseventexposure;

static int hf_json_3gpp_suppfeat_naf_eventexposure_29_pereventrepreq;
static int hf_json_3gpp_suppfeat_naf_eventexposure_30_relativeproximity;

static int hf_json_3gpp_suppfeat_nlmf_broadcast_1_es3xx;

static int hf_json_3gpp_suppfeat_nlmf_loc_1_es3xx;
static int hf_json_3gpp_suppfeat_nlmf_loc_2_sat;
static int hf_json_3gpp_suppfeat_nlmf_loc_3_mutiqos;
static int hf_json_3gpp_suppfeat_nlmf_loc_4_mbsr;

static int hf_json_3gpp_suppfeat_nlmf_loc_5_ranging_sl;
static int hf_json_3gpp_suppfeat_nlmf_loc_6_intres;
static int hf_json_3gpp_suppfeat_nlmf_loc_7_cimlr;

static int hf_json_3gpp_suppfeat_npcf_am_1_slicesupport;
static int hf_json_3gpp_suppfeat_npcf_am_2_pendingtransaction;
static int hf_json_3gpp_suppfeat_npcf_am_3_ueambrauthorization;
static int hf_json_3gpp_suppfeat_npcf_am_4_dnnreplacementcontrol;

static int hf_json_3gpp_suppfeat_npcf_am_5_multipleaccesstypes;
static int hf_json_3gpp_suppfeat_npcf_am_6_wirelinewirelessconvergence;
static int hf_json_3gpp_suppfeat_npcf_am_7_immediatereport;
static int hf_json_3gpp_suppfeat_npcf_am_8_es3xx;

static int hf_json_3gpp_suppfeat_npcf_am_9_ueslicembrauthorization;
static int hf_json_3gpp_suppfeat_npcf_am_10_aminfluence;
static int hf_json_3gpp_suppfeat_npcf_am_11_enena;
static int hf_json_3gpp_suppfeat_npcf_am_12_targetnssai;

static int hf_json_3gpp_suppfeat_npcf_am_13_5gaccessstratumtime;

static int hf_json_3gpp_suppfeat_npcf_sm_1_tsc;
static int hf_json_3gpp_suppfeat_npcf_sm_2_resshare;
static int hf_json_3gpp_suppfeat_npcf_sm_3_3gpppsdataoff;
static int hf_json_3gpp_suppfeat_npcf_sm_4_adc;

static int hf_json_3gpp_suppfeat_npcf_sm_5_umc;
static int hf_json_3gpp_suppfeat_npcf_sm_6_netloc;
static int hf_json_3gpp_suppfeat_npcf_sm_7_rannascause;
static int hf_json_3gpp_suppfeat_npcf_sm_8_provafsignalflow;

static int hf_json_3gpp_suppfeat_npcf_sm_9_pcscfrestorationenhancement;
static int hf_json_3gpp_suppfeat_npcf_sm_10_pra;
static int hf_json_3gpp_suppfeat_npcf_sm_11_ruleversioning;
static int hf_json_3gpp_suppfeat_npcf_sm_12_sponsoredconnectivity;

static int hf_json_3gpp_suppfeat_npcf_sm_13_ransupportinfo;
static int hf_json_3gpp_suppfeat_npcf_sm_14_policyupdatewhenuesuspends;
static int hf_json_3gpp_suppfeat_npcf_sm_15_accesstypecondition;
static int hf_json_3gpp_suppfeat_npcf_sm_16_multiipv6addrprefix;

static int hf_json_3gpp_suppfeat_npcf_sm_17_sessionruleerrorhandling;
static int hf_json_3gpp_suppfeat_npcf_sm_18_af_charging_identifier;
static int hf_json_3gpp_suppfeat_npcf_sm_19_atsss;
static int hf_json_3gpp_suppfeat_npcf_sm_20_pendingtransaction;

static int hf_json_3gpp_suppfeat_npcf_sm_21_urllc;
static int hf_json_3gpp_suppfeat_npcf_sm_22_macaddressrange;
static int hf_json_3gpp_suppfeat_npcf_sm_23_wwc;
static int hf_json_3gpp_suppfeat_npcf_sm_24_qosmonitoring;

static int hf_json_3gpp_suppfeat_npcf_sm_25_authorizationwithrequiredqos;
static int hf_json_3gpp_suppfeat_npcf_sm_26_enhancedbackgrounddatatransfer;
static int hf_json_3gpp_suppfeat_npcf_sm_27_dn_authorization;
static int hf_json_3gpp_suppfeat_npcf_sm_28_pdusessionrelcause;

static int hf_json_3gpp_suppfeat_npcf_sm_29_samepcf;
static int hf_json_3gpp_suppfeat_npcf_sm_30_adcmultiredirection;
static int hf_json_3gpp_suppfeat_npcf_sm_31_respbasedsessionrel;
static int hf_json_3gpp_suppfeat_npcf_sm_32_timesensitivenetworking;

static int hf_json_3gpp_suppfeat_npcf_sm_33_emdbv;
static int hf_json_3gpp_suppfeat_npcf_sm_34_dnnselectionmode;
static int hf_json_3gpp_suppfeat_npcf_sm_35_epsfallbackreport;
static int hf_json_3gpp_suppfeat_npcf_sm_36_policydecisionerrorhandling;

static int hf_json_3gpp_suppfeat_npcf_sm_37_ddneventpolicycontrol;
static int hf_json_3gpp_suppfeat_npcf_sm_38_reallocationofcredit;
static int hf_json_3gpp_suppfeat_npcf_sm_39_bdtpolicyrenegotiation;
static int hf_json_3gpp_suppfeat_npcf_sm_40_extpolicydecisionerrorhandling;

static int hf_json_3gpp_suppfeat_npcf_sm_41_immediatetermination;
static int hf_json_3gpp_suppfeat_npcf_sm_42_aggregateduelocchanges;
static int hf_json_3gpp_suppfeat_npcf_sm_43_es3xx;
static int hf_json_3gpp_suppfeat_npcf_sm_44_groupidlistchange;

static int hf_json_3gpp_suppfeat_npcf_sm_45_disableuenotification;
static int hf_json_3gpp_suppfeat_npcf_sm_46_offlinechonly;
static int hf_json_3gpp_suppfeat_npcf_sm_47_dual_connectivity_redundant_up_paths;
static int hf_json_3gpp_suppfeat_npcf_sm_48_ddneventpolicycontrol2;

static int hf_json_3gpp_suppfeat_npcf_sm_49_vplmn_qos_control;
static int hf_json_3gpp_suppfeat_npcf_sm_50_2g3giwk;
static int hf_json_3gpp_suppfeat_npcf_sm_51_timesensitivecommunication;
static int hf_json_3gpp_suppfeat_npcf_sm_52_enedge;

static int hf_json_3gpp_suppfeat_npcf_sm_53_satbackhaulcategorychg;
static int hf_json_3gpp_suppfeat_npcf_sm_54_chfsetsupport;
static int hf_json_3gpp_suppfeat_npcf_sm_55_enatsss;
static int hf_json_3gpp_suppfeat_npcf_sm_56_mpsfordts;

static int hf_json_3gpp_suppfeat_npcf_sm_57_routinginforemoval;
static int hf_json_3gpp_suppfeat_npcf_sm_58_epra;
static int hf_json_3gpp_suppfeat_npcf_sm_59_aminfluence;
static int hf_json_3gpp_suppfeat_npcf_sm_60_pvssupport;

static int hf_json_3gpp_suppfeat_npcf_sm_61_enena;
static int hf_json_3gpp_suppfeat_npcf_sm_62_biumr;
static int hf_json_3gpp_suppfeat_npcf_sm_63_easipreplacement;
static int hf_json_3gpp_suppfeat_npcf_sm_64_exposuretoeas;

static int hf_json_3gpp_suppfeat_npcf_sm_65_simultconnectivity;
static int hf_json_3gpp_suppfeat_npcf_sm_66_sgwrest;
static int hf_json_3gpp_suppfeat_npcf_sm_67_releasetoreactivate;
static int hf_json_3gpp_suppfeat_npcf_sm_68_easdiscovery;

static int hf_json_3gpp_suppfeat_npcf_sm_69_accnetchargid_string;

static int hf_json_3gpp_suppfeat_npcf_ue_1_pendingtransaction;
static int hf_json_3gpp_suppfeat_npcf_ue_2_plmnchange;
static int hf_json_3gpp_suppfeat_npcf_ue_3_connectivitystatechange;
static int hf_json_3gpp_suppfeat_npcf_ue_4_v2x;

static int hf_json_3gpp_suppfeat_npcf_ue_5_groupidlistchange;
static int hf_json_3gpp_suppfeat_npcf_ue_6_immediatereport;
static int hf_json_3gpp_suppfeat_npcf_ue_7_errorresponse;
static int hf_json_3gpp_suppfeat_npcf_ue_8_es3xx;

static int hf_json_3gpp_suppfeat_npcf_ue_9_prose;


static int hf_json_3gpp_suppfeat_nsmf_pdusession_1_ciot;
static int hf_json_3gpp_suppfeat_nsmf_pdusession_2_mapdu;
static int hf_json_3gpp_suppfeat_nsmf_pdusession_3_dtssa;
static int hf_json_3gpp_suppfeat_nsmf_pdusession_4_carpt;

static int hf_json_3gpp_suppfeat_nsmf_pdusession_5_ctxtr;
static int hf_json_3gpp_suppfeat_nsmf_pdusession_6_vqos;
static int hf_json_3gpp_suppfeat_nsmf_pdusession_7_hofail;
static int hf_json_3gpp_suppfeat_nsmf_pdusession_8_es3xx;

static int hf_json_3gpp_suppfeat_nsmf_pdusession_9_dce2er;
static int hf_json_3gpp_suppfeat_nsmf_pdusession_10_aasn;
static int hf_json_3gpp_suppfeat_nsmf_pdusession_11_enedge;
static int hf_json_3gpp_suppfeat_nsmf_pdusession_12_scpbu;

static int hf_json_3gpp_suppfeat_nsmf_pdusession_13_enpn;
static int hf_json_3gpp_suppfeat_nsmf_pdusession_14_spae;
static int hf_json_3gpp_suppfeat_nsmf_pdusession_15_5gsat;
static int hf_json_3gpp_suppfeat_nsmf_pdusession_16_upipe;

static int hf_json_3gpp_suppfeat_nsmf_pdusession_17_biumr;
static int hf_json_3gpp_suppfeat_nsmf_pdusession_18_acscr;
static int hf_json_3gpp_suppfeat_nsmf_pdusession_19_psetr;
static int hf_json_3gpp_suppfeat_nsmf_pdusession_20_dlset;

static int hf_json_3gpp_suppfeat_nsmf_pdusession_21_n9fsc;

static int hf_json_3gpp_suppfeat_nudm_sdm_1_shareddata;
static int hf_json_3gpp_suppfeat_nudm_sdm_2_immediatereport;
static int hf_json_3gpp_suppfeat_nudm_sdm_3_patchreport;
static int hf_json_3gpp_suppfeat_nudm_sdm_4_nssaa;

static int hf_json_3gpp_suppfeat_nudm_sdm_5_cagfeature;
static int hf_json_3gpp_suppfeat_nudm_sdm_6_shareddatatreatment;
static int hf_json_3gpp_suppfeat_nudm_sdm_7_sortransparentsupport;
static int hf_json_3gpp_suppfeat_nudm_sdm_8_nsac;

static int hf_json_3gpp_suppfeat_nudm_sdm_9_sharedsmsubsdata;
static int hf_json_3gpp_suppfeat_nudm_sdm_10_ena;
static int hf_json_3gpp_suppfeat_nudm_sdm_11_nssrg;
static int hf_json_3gpp_suppfeat_nudm_sdm_12_uputransparentsupport;

static int hf_json_3gpp_suppfeat_nudm_sdm_13_limitedsubscriptions;
static int hf_json_3gpp_suppfeat_nudm_sdm_14_snpn_id;
static int hf_json_3gpp_suppfeat_nudm_sdm_15_ueconsmfdatasubfilter;
static int hf_json_3gpp_suppfeat_nudm_sdm_16_tempslicesupport;

static int hf_json_3gpp_suppfeat_nudm_sdm_17_expectedbehaviourmap;
static int hf_json_3gpp_suppfeat_nudm_sdm_18_shareddataext;
static int hf_json_3gpp_suppfeat_nudm_sdm_19_snpnidext;
static int hf_json_3gpp_suppfeat_nudm_sdm_20_caginfowithvalidityperiods;

static int hf_json_3gpp_suppfeat_nudm_uecm_1_shareddata;
static int hf_json_3gpp_suppfeat_nudm_uecm_2_patchreport;
static int hf_json_3gpp_suppfeat_nudm_uecm_3_shareddatatreatment;
static int hf_json_3gpp_suppfeat_nudm_uecm_4_cagfeature;

static int hf_json_3gpp_suppfeat_nudm_uecm_5_deregistrationresponsebody;

static int hf_json_3gpp_suppfeat_nudm_ee_1_patchreport;
static int hf_json_3gpp_suppfeat_nudm_ee_2_enena;
static int hf_json_3gpp_suppfeat_nudm_ee_3_dgem;
static int hf_json_3gpp_suppfeat_nudm_ee_4_iersr;

static int hf_json_3gpp_suppfeat_nudm_ee_5_enaph3;

static int hf_json_3gpp_suppfeat_nudm_pp_1_patchreport;
static int hf_json_3gpp_suppfeat_nudm_pp_2_expectedbehaviourmap;
static int hf_json_3gpp_suppfeat_nudm_pp_3_membersdata;

#define NAF_EVENTEXPOSTURE "/naf-eventexposure/v1/"
#define NLMF_BROADCAST "/lmf-broadcast/v1/"
#define NLMF_LOC "/lmf-loc/v1/"
#define NPCF_AM_POLICY_CONTROL "/npcf-am-policy-control/v1/policies"
#define NPCF_SM_POLICY_CONTROL "/npcf-smpolicycontrol/v1/sm-policies" /* inconsistency naming from 3gpp */
#define NPCF_UE_POLICY_CONTROL "/npcf-ue-policy-control/v1/policies"
#define NSMF_PDU_SESSION "/nsmf-pdusession/v1/"
#define NUDM_EE "/nudm-ee/v1/"
#define NUDM_EUCM "/nudm-eucm/v1/"
#define NUDM_SDM "/nudm-sdm/v2/"
#define NUDM_PP "/nudm-pp/v1/"


/* Functions to sub dissect json content */
static void
dissect_base64decoded_eps_ie(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo, int offset, int len, const char* key_str _U_)
{
	/* base64-encoded characters, encoding the
	 * EPS IE specified in 3GPP TS 29.274.
	 */

	proto_item* ti;
	proto_tree* sub_tree;
	tvbuff_t* bin_tvb = base64_tvb_to_new_tvb(tvb, offset, len);
	int bin_tvb_length = tvb_reported_length(bin_tvb);
	add_new_data_source(pinfo, bin_tvb, "Base64 decoded");
	ti = proto_tree_add_item(tree, hf_json_3gpp_binary_data, bin_tvb, 0, bin_tvb_length, ENC_NA);
	sub_tree = proto_item_add_subtree(ti, ett_json_base64decoded_eps_ie);
	dissect_gtpv2_ie_common(bin_tvb, pinfo, sub_tree, 0, 0/* Message type 0, Reserved */, NULL, 0);

	return;
}

static void
dissect_base64decoded_nas5g_ie(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo, int offset, int len, const char* key_str)
{
	/* base64-encoded characters, encoding the
	 * NAS-5G IE specified in 3GPP TS 24.501.
	 */
	proto_item* ti;
	proto_tree* sub_tree;
	tvbuff_t* bin_tvb = base64_tvb_to_new_tvb(tvb, offset, len);
	int bin_tvb_length = tvb_reported_length(bin_tvb);
	add_new_data_source(pinfo, bin_tvb, "Base64 decoded");
	ti = proto_tree_add_item(tree, hf_json_3gpp_binary_data, bin_tvb, 0, bin_tvb_length, ENC_NA);
	sub_tree = proto_item_add_subtree(ti, ett_json_base64decoded_nas5g_ie);

	if (strcmp(key_str, "qosRules") == 0) {
		/* qosRules
		 * This IE shall contain the QoS Rule(s) associated to the QoS flow to be sent to the UE.
		 * It shall be encoded as the Qos rules IE specified in clause 9.11.4.13 of 3GPP TS 24.501 (starting from octet 4).
		 */
		de_nas_5gs_sm_qos_rules(bin_tvb, sub_tree, pinfo, 0, bin_tvb_length, NULL, 0);
	}
	else if (strcmp(key_str, "qosFlowDescription") == 0) {
		/* qosFlowDescription
		 * When present, this IE shall contain the description of the QoS Flow level Qos parameters to be sent to the UE.
		 * It shall be encoded as the Qos flow descriptions IE specified in clause 9.11.4.12 of 3GPP TS 24.501 (starting from octet 1),
		 * encoding one single Qos flow description for the QoS flow to be set up.
		 */
		elem_telv(bin_tvb, sub_tree, pinfo, (uint8_t) 0x79, 18 /* NAS_5GS_PDU_TYPE_SM */, 11 /* DE_NAS_5GS_SM_QOS_FLOW_DES */, 0, bin_tvb_length, NULL);
	}

	return;
}

static void
dissect_3gpp_supportfeatures_naf_eventexposure(tvbuff_t* suppfeat_tvb, proto_tree* sub_tree, packet_info* pinfo _U_, int offset _U_, int len, uint8_t *hex_ascii)
{
	int offset_reverse = len - 1;

	/* TS 29.517 ch5.8 Feature negotiation */

	static int * const json_3gpp_suppfeat_naf_eventexposure_list_1[] = {
		&hf_json_3gpp_suppfeat_naf_eventexposure_1_serviceexperience,
		&hf_json_3gpp_suppfeat_naf_eventexposure_2_uemobility,
		&hf_json_3gpp_suppfeat_naf_eventexposure_3_uecommunication,
		&hf_json_3gpp_suppfeat_naf_eventexposure_4_exceptions,
		NULL
	};
	proto_tree_add_bitmask_list_value(sub_tree, suppfeat_tvb, offset_reverse, 1, json_3gpp_suppfeat_naf_eventexposure_list_1, g_ascii_xdigit_value(hex_ascii[offset_reverse]));
	offset_reverse--;

	if (offset_reverse == -1) {
		return;
	}

	static int * const json_3gpp_suppfeat_naf_eventexposure_list_2[] = {
		&hf_json_3gpp_suppfeat_naf_eventexposure_5_es3xx,
		&hf_json_3gpp_suppfeat_naf_eventexposure_6_enena,
		&hf_json_3gpp_suppfeat_naf_eventexposure_7_userdatacongestion,
		&hf_json_3gpp_suppfeat_naf_eventexposure_8_performancedata,
		NULL
	};
	proto_tree_add_bitmask_list_value(sub_tree, suppfeat_tvb, offset_reverse, 1, json_3gpp_suppfeat_naf_eventexposure_list_2, g_ascii_xdigit_value(hex_ascii[offset_reverse]));
	offset_reverse--;

	if (offset_reverse == -1) {
		return;
	}

	static int * const json_3gpp_suppfeat_naf_eventexposure_list_3[] = {
		&hf_json_3gpp_suppfeat_naf_eventexposure_9_dispersion,
		&hf_json_3gpp_suppfeat_naf_eventexposure_10_collectivebehaviour,
		&hf_json_3gpp_suppfeat_naf_eventexposure_11_serviceexperienceext,
		&hf_json_3gpp_suppfeat_naf_eventexposure_12_msqoemetrics,
		NULL
	};
	proto_tree_add_bitmask_list_value(sub_tree, suppfeat_tvb, offset_reverse, 1, json_3gpp_suppfeat_naf_eventexposure_list_3, g_ascii_xdigit_value(hex_ascii[offset_reverse]));
	offset_reverse--;

	if (offset_reverse == -1) {
		return;
	}

	static int * const json_3gpp_suppfeat_naf_eventexposure_list_4[] = {
		&hf_json_3gpp_suppfeat_naf_eventexposure_13_msconsumption,
		&hf_json_3gpp_suppfeat_naf_eventexposure_14_msnetassinvocation,
		&hf_json_3gpp_suppfeat_naf_eventexposure_15_msdynpolicyinvocation,
		&hf_json_3gpp_suppfeat_naf_eventexposure_16_msaccessactivity,
		NULL
	};
	proto_tree_add_bitmask_list_value(sub_tree, suppfeat_tvb, offset_reverse, 1, json_3gpp_suppfeat_naf_eventexposure_list_4, g_ascii_xdigit_value(hex_ascii[offset_reverse]));
	offset_reverse--;

	if (offset_reverse == -1) {
		return;
	}

	static int * const json_3gpp_suppfeat_naf_eventexposure_list_5[] = {
		&hf_json_3gpp_suppfeat_naf_eventexposure_17_dataaccprofileid,
		&hf_json_3gpp_suppfeat_naf_eventexposure_18_allapplications,
		&hf_json_3gpp_suppfeat_naf_eventexposure_19_gnssassistdata,
		&hf_json_3gpp_suppfeat_naf_eventexposure_20_performancedataext_aiml,
		NULL
	};
	proto_tree_add_bitmask_list_value(sub_tree, suppfeat_tvb, offset_reverse, 1, json_3gpp_suppfeat_naf_eventexposure_list_5, g_ascii_xdigit_value(hex_ascii[offset_reverse]));
	offset_reverse--;

	if (offset_reverse == -1) {
		return;
	}

	static int * const json_3gpp_suppfeat_naf_eventexposure_list_6[] = {
		&hf_json_3gpp_suppfeat_naf_eventexposure_21_uemobilityext_aiml,
		&hf_json_3gpp_suppfeat_naf_eventexposure_22_enperformancedata,
		&hf_json_3gpp_suppfeat_naf_eventexposure_23_uecommunicationext_ena,
		&hf_json_3gpp_suppfeat_naf_eventexposure_24_serviceexperienceext2_ena,
		NULL
	};
	proto_tree_add_bitmask_list_value(sub_tree, suppfeat_tvb, offset_reverse, 1, json_3gpp_suppfeat_naf_eventexposure_list_6, g_ascii_xdigit_value(hex_ascii[offset_reverse]));
	offset_reverse--;

	if (offset_reverse == -1) {
		return;
	}

	static int * const json_3gpp_suppfeat_naf_eventexposure_list_7[] = {
		&hf_json_3gpp_suppfeat_naf_eventexposure_25_enhdatamgmt,
		&hf_json_3gpp_suppfeat_naf_eventexposure_26_exteventfilters,
		&hf_json_3gpp_suppfeat_naf_eventexposure_27_datavoltransfertime,
		&hf_json_3gpp_suppfeat_naf_eventexposure_28_mseventexposure,
		NULL
	};
	proto_tree_add_bitmask_list_value(sub_tree, suppfeat_tvb, offset_reverse, 1, json_3gpp_suppfeat_naf_eventexposure_list_7, g_ascii_xdigit_value(hex_ascii[offset_reverse]));
	offset_reverse--;

	if (offset_reverse == -1) {
		return;
	}

	static int * const json_3gpp_suppfeat_naf_eventexposure_list_8[] = {
		&hf_json_3gpp_suppfeat_naf_eventexposure_29_pereventrepreq,
		&hf_json_3gpp_suppfeat_naf_eventexposure_30_relativeproximity,
		NULL
	};
	proto_tree_add_bitmask_list_value(sub_tree, suppfeat_tvb, offset_reverse, 1, json_3gpp_suppfeat_naf_eventexposure_list_8, g_ascii_xdigit_value(hex_ascii[offset_reverse]));
	offset_reverse--;

	if (offset_reverse == -1) {
		return;
	}

	if (offset_reverse > -1) {
		proto_tree_add_format_text(sub_tree, suppfeat_tvb, 0, (offset_reverse - len));
	}
}

static void
dissect_3gpp_supportfeatures_nlmf_broadcast(tvbuff_t* suppfeat_tvb, proto_tree* sub_tree, packet_info* pinfo _U_, int offset _U_, int len, uint8_t *hex_ascii)
{
	int offset_reverse = len - 1;

	/* TS 29.572 ch6.2.9 Feature negotiation */

	static int * const json_3gpp_suppfeat_nlmf_broadcast_list_1[] = {
		&hf_json_3gpp_suppfeat_nlmf_broadcast_1_es3xx,
		NULL
	};
	proto_tree_add_bitmask_list_value(sub_tree, suppfeat_tvb, offset_reverse, 1, json_3gpp_suppfeat_nlmf_broadcast_list_1, g_ascii_xdigit_value(hex_ascii[offset_reverse]));
	offset_reverse--;

	if (offset_reverse == -1) {
		return;
	}

	static int * const json_3gpp_suppfeat_nlmf_loc_list_2[] = {
		&hf_json_3gpp_suppfeat_nlmf_loc_5_ranging_sl,
		&hf_json_3gpp_suppfeat_nlmf_loc_6_intres,
		&hf_json_3gpp_suppfeat_nlmf_loc_7_cimlr,
		NULL
	};
	proto_tree_add_bitmask_list_value(sub_tree, suppfeat_tvb, offset_reverse, 1, json_3gpp_suppfeat_nlmf_loc_list_2, g_ascii_xdigit_value(hex_ascii[offset_reverse]));
	offset_reverse--;

	if (offset_reverse == -1) {
		return;
	}

	if (offset_reverse > -1) {
		proto_tree_add_format_text(sub_tree, suppfeat_tvb, 0, (offset_reverse - len));
	}
}

static void
dissect_3gpp_supportfeatures_nlmf_loc(tvbuff_t* suppfeat_tvb, proto_tree* sub_tree, packet_info* pinfo _U_, int offset _U_, int len, uint8_t *hex_ascii)
{
	int offset_reverse = len - 1;

	/* TS 29.572 ch6.1.9 Feature negotiation */

	static int * const json_3gpp_suppfeat_nlmf_loc_list_1[] = {
		&hf_json_3gpp_suppfeat_nlmf_loc_1_es3xx,
		&hf_json_3gpp_suppfeat_nlmf_loc_2_sat,
		&hf_json_3gpp_suppfeat_nlmf_loc_3_mutiqos,
		&hf_json_3gpp_suppfeat_nlmf_loc_4_mbsr,
		NULL
	};
	proto_tree_add_bitmask_list_value(sub_tree, suppfeat_tvb, offset_reverse, 1, json_3gpp_suppfeat_nlmf_loc_list_1, g_ascii_xdigit_value(hex_ascii[offset_reverse]));
	offset_reverse--;

	if (offset_reverse == -1) {
		return;
	}

	static int * const json_3gpp_suppfeat_nlmf_loc_list_2[] = {
		&hf_json_3gpp_suppfeat_nlmf_loc_5_ranging_sl,
		&hf_json_3gpp_suppfeat_nlmf_loc_6_intres,
		&hf_json_3gpp_suppfeat_nlmf_loc_7_cimlr,
		NULL
	};
	proto_tree_add_bitmask_list_value(sub_tree, suppfeat_tvb, offset_reverse, 1, json_3gpp_suppfeat_nlmf_loc_list_2, g_ascii_xdigit_value(hex_ascii[offset_reverse]));
	offset_reverse--;

	if (offset_reverse == -1) {
		return;
	}

	if (offset_reverse > -1) {
		proto_tree_add_format_text(sub_tree, suppfeat_tvb, 0, (offset_reverse - len));
	}
}

static void
dissect_3gpp_supportfeatures_npcf_am_policy_control(tvbuff_t* suppfeat_tvb, proto_tree* sub_tree, packet_info* pinfo _U_, int offset _U_, int len, uint8_t *hex_ascii)
{
	int offset_reverse = len - 1;

	/* TS 29.507 ch5.8 Feature negotiation */

	static int * const json_3gpp_suppfeat_npcf_am_list_1[] = {
		&hf_json_3gpp_suppfeat_npcf_am_1_slicesupport,
		&hf_json_3gpp_suppfeat_npcf_am_2_pendingtransaction,
		&hf_json_3gpp_suppfeat_npcf_am_3_ueambrauthorization,
		&hf_json_3gpp_suppfeat_npcf_am_4_dnnreplacementcontrol,
		NULL
	};
	proto_tree_add_bitmask_list_value(sub_tree, suppfeat_tvb, offset_reverse, 1, json_3gpp_suppfeat_npcf_am_list_1, g_ascii_xdigit_value(hex_ascii[offset_reverse]));
	offset_reverse--;

	if (offset_reverse == -1) {
		return;
	}

	static int * const json_3gpp_suppfeat_npcf_am_list_2[] = {
		&hf_json_3gpp_suppfeat_npcf_am_5_multipleaccesstypes,
		&hf_json_3gpp_suppfeat_npcf_am_6_wirelinewirelessconvergence,
		&hf_json_3gpp_suppfeat_npcf_am_7_immediatereport,
		&hf_json_3gpp_suppfeat_npcf_am_8_es3xx,
		NULL
	};
	proto_tree_add_bitmask_list_value(sub_tree, suppfeat_tvb, offset_reverse, 1, json_3gpp_suppfeat_npcf_am_list_2, g_ascii_xdigit_value(hex_ascii[offset_reverse]));
	offset_reverse--;

	if (offset_reverse == -1) {
		return;
	}

	static int * const json_3gpp_suppfeat_npcf_am_list_3[] = {
		&hf_json_3gpp_suppfeat_npcf_am_9_ueslicembrauthorization,
		&hf_json_3gpp_suppfeat_npcf_am_10_aminfluence,
		&hf_json_3gpp_suppfeat_npcf_am_11_enena,
		&hf_json_3gpp_suppfeat_npcf_am_12_targetnssai,
		NULL
	};
	proto_tree_add_bitmask_list_value(sub_tree, suppfeat_tvb, offset_reverse, 1, json_3gpp_suppfeat_npcf_am_list_3, g_ascii_xdigit_value(hex_ascii[offset_reverse]));
	offset_reverse--;

	if (offset_reverse == -1) {
		return;
	}

	static int * const json_3gpp_suppfeat_npcf_am_list_4[] = {
		&hf_json_3gpp_suppfeat_npcf_am_13_5gaccessstratumtime,
		NULL
	};
	proto_tree_add_bitmask_list_value(sub_tree, suppfeat_tvb, offset_reverse, 1, json_3gpp_suppfeat_npcf_am_list_4, g_ascii_xdigit_value(hex_ascii[offset_reverse]));
	offset_reverse--;

	if (offset_reverse == -1) {
		return;
	}

	if (offset_reverse > -1) {
		proto_tree_add_format_text(sub_tree, suppfeat_tvb, 0, (offset_reverse - len));
	}
}

static void
dissect_3gpp_supportfeatures_npcf_sm_policy_control(tvbuff_t* suppfeat_tvb, proto_tree* sub_tree, packet_info* pinfo _U_, int offset _U_, int len, uint8_t *hex_ascii)
{
	int offset_reverse = len - 1;

	/* TS 29.512 ch5.8 Feature negotiation */

	static int * const json_3gpp_suppfeat_npcf_sm_list_1[] = {
		&hf_json_3gpp_suppfeat_npcf_sm_1_tsc,
		&hf_json_3gpp_suppfeat_npcf_sm_2_resshare,
		&hf_json_3gpp_suppfeat_npcf_sm_3_3gpppsdataoff,
		&hf_json_3gpp_suppfeat_npcf_sm_4_adc,
		NULL
	};
	proto_tree_add_bitmask_list_value(sub_tree, suppfeat_tvb, offset_reverse, 1, json_3gpp_suppfeat_npcf_sm_list_1, g_ascii_xdigit_value(hex_ascii[offset_reverse]));
	offset_reverse--;

	if (offset_reverse == -1) {
		return;
	}

	static int * const json_3gpp_suppfeat_npcf_sm_list_2[] = {
		&hf_json_3gpp_suppfeat_npcf_sm_5_umc,
		&hf_json_3gpp_suppfeat_npcf_sm_6_netloc,
		&hf_json_3gpp_suppfeat_npcf_sm_7_rannascause,
		&hf_json_3gpp_suppfeat_npcf_sm_8_provafsignalflow,
		NULL
	};
	proto_tree_add_bitmask_list_value(sub_tree, suppfeat_tvb, offset_reverse, 1, json_3gpp_suppfeat_npcf_sm_list_2, g_ascii_xdigit_value(hex_ascii[offset_reverse]));
	offset_reverse--;

	if (offset_reverse == -1) {
		return;
	}

	static int * const json_3gpp_suppfeat_npcf_sm_list_3[] = {
		&hf_json_3gpp_suppfeat_npcf_sm_9_pcscfrestorationenhancement,
		&hf_json_3gpp_suppfeat_npcf_sm_10_pra,
		&hf_json_3gpp_suppfeat_npcf_sm_11_ruleversioning,
		&hf_json_3gpp_suppfeat_npcf_sm_12_sponsoredconnectivity,
		NULL
	};
	proto_tree_add_bitmask_list_value(sub_tree, suppfeat_tvb, offset_reverse, 1, json_3gpp_suppfeat_npcf_sm_list_3, g_ascii_xdigit_value(hex_ascii[offset_reverse]));
	offset_reverse--;

	if (offset_reverse == -1) {
		return;
	}

	static int * const json_3gpp_suppfeat_npcf_sm_list_4[] = {
		&hf_json_3gpp_suppfeat_npcf_sm_13_ransupportinfo,
		&hf_json_3gpp_suppfeat_npcf_sm_14_policyupdatewhenuesuspends,
		&hf_json_3gpp_suppfeat_npcf_sm_15_accesstypecondition,
		&hf_json_3gpp_suppfeat_npcf_sm_16_multiipv6addrprefix,
		NULL
	};
	proto_tree_add_bitmask_list_value(sub_tree, suppfeat_tvb, offset_reverse, 1, json_3gpp_suppfeat_npcf_sm_list_4, g_ascii_xdigit_value(hex_ascii[offset_reverse]));
	offset_reverse--;

	if (offset_reverse == -1) {
		return;
	}

	static int * const json_3gpp_suppfeat_npcf_sm_list_5[] = {
		&hf_json_3gpp_suppfeat_npcf_sm_17_sessionruleerrorhandling,
		&hf_json_3gpp_suppfeat_npcf_sm_18_af_charging_identifier,
		&hf_json_3gpp_suppfeat_npcf_sm_19_atsss,
		&hf_json_3gpp_suppfeat_npcf_sm_20_pendingtransaction,
		NULL
	};
	proto_tree_add_bitmask_list_value(sub_tree, suppfeat_tvb, offset_reverse, 1, json_3gpp_suppfeat_npcf_sm_list_5, g_ascii_xdigit_value(hex_ascii[offset_reverse]));
	offset_reverse--;

	if (offset_reverse == -1) {
		return;
	}

	static int * const json_3gpp_suppfeat_npcf_sm_list_6[] = {
		&hf_json_3gpp_suppfeat_npcf_sm_21_urllc,
		&hf_json_3gpp_suppfeat_npcf_sm_22_macaddressrange,
		&hf_json_3gpp_suppfeat_npcf_sm_23_wwc,
		&hf_json_3gpp_suppfeat_npcf_sm_24_qosmonitoring,
		NULL
	};
	proto_tree_add_bitmask_list_value(sub_tree, suppfeat_tvb, offset_reverse, 1, json_3gpp_suppfeat_npcf_sm_list_6, g_ascii_xdigit_value(hex_ascii[offset_reverse]));
	offset_reverse--;

	if (offset_reverse == -1) {
		return;
	}

	static int * const json_3gpp_suppfeat_npcf_sm_list_7[] = {
		&hf_json_3gpp_suppfeat_npcf_sm_25_authorizationwithrequiredqos,
		&hf_json_3gpp_suppfeat_npcf_sm_26_enhancedbackgrounddatatransfer,
		&hf_json_3gpp_suppfeat_npcf_sm_27_dn_authorization,
		&hf_json_3gpp_suppfeat_npcf_sm_28_pdusessionrelcause,
		NULL
	};
	proto_tree_add_bitmask_list_value(sub_tree, suppfeat_tvb, offset_reverse, 1, json_3gpp_suppfeat_npcf_sm_list_7, g_ascii_xdigit_value(hex_ascii[offset_reverse]));
	offset_reverse--;

	if (offset_reverse == -1) {
		return;
	}

	static int * const json_3gpp_suppfeat_npcf_sm_list_8[] = {
		&hf_json_3gpp_suppfeat_npcf_sm_29_samepcf,
		&hf_json_3gpp_suppfeat_npcf_sm_30_adcmultiredirection,
		&hf_json_3gpp_suppfeat_npcf_sm_31_respbasedsessionrel,
		&hf_json_3gpp_suppfeat_npcf_sm_32_timesensitivenetworking,
		NULL
	};
	proto_tree_add_bitmask_list_value(sub_tree, suppfeat_tvb, offset_reverse, 1, json_3gpp_suppfeat_npcf_sm_list_8, g_ascii_xdigit_value(hex_ascii[offset_reverse]));
	offset_reverse--;

	if (offset_reverse == -1) {
		return;
	}

	static int * const json_3gpp_suppfeat_npcf_sm_list_9[] = {
		&hf_json_3gpp_suppfeat_npcf_sm_33_emdbv,
		&hf_json_3gpp_suppfeat_npcf_sm_34_dnnselectionmode,
		&hf_json_3gpp_suppfeat_npcf_sm_35_epsfallbackreport,
		&hf_json_3gpp_suppfeat_npcf_sm_36_policydecisionerrorhandling,
		NULL
	};
	proto_tree_add_bitmask_list_value(sub_tree, suppfeat_tvb, offset_reverse, 1, json_3gpp_suppfeat_npcf_sm_list_9, g_ascii_xdigit_value(hex_ascii[offset_reverse]));
	offset_reverse--;

	if (offset_reverse == -1) {
		return;
	}

	static int * const json_3gpp_suppfeat_npcf_sm_list_10[] = {
		&hf_json_3gpp_suppfeat_npcf_sm_37_ddneventpolicycontrol,
		&hf_json_3gpp_suppfeat_npcf_sm_38_reallocationofcredit,
		&hf_json_3gpp_suppfeat_npcf_sm_39_bdtpolicyrenegotiation,
		&hf_json_3gpp_suppfeat_npcf_sm_40_extpolicydecisionerrorhandling,
		NULL
	};
	proto_tree_add_bitmask_list_value(sub_tree, suppfeat_tvb, offset_reverse, 1, json_3gpp_suppfeat_npcf_sm_list_10, g_ascii_xdigit_value(hex_ascii[offset_reverse]));
	offset_reverse--;

	if (offset_reverse == -1) {
		return;
	}

	static int * const json_3gpp_suppfeat_npcf_sm_list_11[] = {
		&hf_json_3gpp_suppfeat_npcf_sm_41_immediatetermination,
		&hf_json_3gpp_suppfeat_npcf_sm_42_aggregateduelocchanges,
		&hf_json_3gpp_suppfeat_npcf_sm_43_es3xx,
		&hf_json_3gpp_suppfeat_npcf_sm_44_groupidlistchange,
		NULL
	};
	proto_tree_add_bitmask_list_value(sub_tree, suppfeat_tvb, offset_reverse, 1, json_3gpp_suppfeat_npcf_sm_list_11, g_ascii_xdigit_value(hex_ascii[offset_reverse]));
	offset_reverse--;

	if (offset_reverse == -1) {
		return;
	}

	static int * const json_3gpp_suppfeat_npcf_sm_list_12[] = {
		&hf_json_3gpp_suppfeat_npcf_sm_45_disableuenotification,
		&hf_json_3gpp_suppfeat_npcf_sm_46_offlinechonly,
		&hf_json_3gpp_suppfeat_npcf_sm_47_dual_connectivity_redundant_up_paths,
		&hf_json_3gpp_suppfeat_npcf_sm_48_ddneventpolicycontrol2,
		NULL
	};
	proto_tree_add_bitmask_list_value(sub_tree, suppfeat_tvb, offset_reverse, 1, json_3gpp_suppfeat_npcf_sm_list_12, g_ascii_xdigit_value(hex_ascii[offset_reverse]));
	offset_reverse--;

	if (offset_reverse == -1) {
		return;
	}

	static int * const json_3gpp_suppfeat_npcf_sm_list_13[] = {
		&hf_json_3gpp_suppfeat_npcf_sm_49_vplmn_qos_control,
		&hf_json_3gpp_suppfeat_npcf_sm_50_2g3giwk,
		&hf_json_3gpp_suppfeat_npcf_sm_51_timesensitivecommunication,
		&hf_json_3gpp_suppfeat_npcf_sm_52_enedge,
		NULL
	};
	proto_tree_add_bitmask_list_value(sub_tree, suppfeat_tvb, offset_reverse, 1, json_3gpp_suppfeat_npcf_sm_list_13, g_ascii_xdigit_value(hex_ascii[offset_reverse]));
	offset_reverse--;

	if (offset_reverse == -1) {
		return;
	}

	static int * const json_3gpp_suppfeat_npcf_sm_list_14[] = {
		&hf_json_3gpp_suppfeat_npcf_sm_53_satbackhaulcategorychg,
		&hf_json_3gpp_suppfeat_npcf_sm_54_chfsetsupport,
		&hf_json_3gpp_suppfeat_npcf_sm_55_enatsss,
		&hf_json_3gpp_suppfeat_npcf_sm_56_mpsfordts,
		NULL
	};
	proto_tree_add_bitmask_list_value(sub_tree, suppfeat_tvb, offset_reverse, 1, json_3gpp_suppfeat_npcf_sm_list_14, g_ascii_xdigit_value(hex_ascii[offset_reverse]));
	offset_reverse--;

	if (offset_reverse == -1) {
		return;
	}

	static int * const json_3gpp_suppfeat_npcf_sm_list_15[] = {
		&hf_json_3gpp_suppfeat_npcf_sm_57_routinginforemoval,
		&hf_json_3gpp_suppfeat_npcf_sm_58_epra,
		&hf_json_3gpp_suppfeat_npcf_sm_59_aminfluence,
		&hf_json_3gpp_suppfeat_npcf_sm_60_pvssupport,
		NULL
	};
	proto_tree_add_bitmask_list_value(sub_tree, suppfeat_tvb, offset_reverse, 1, json_3gpp_suppfeat_npcf_sm_list_15, g_ascii_xdigit_value(hex_ascii[offset_reverse]));
	offset_reverse--;

	if (offset_reverse == -1) {
		return;
	}

	static int * const json_3gpp_suppfeat_npcf_sm_list_16[] = {
		&hf_json_3gpp_suppfeat_npcf_sm_61_enena,
		&hf_json_3gpp_suppfeat_npcf_sm_62_biumr,
		&hf_json_3gpp_suppfeat_npcf_sm_63_easipreplacement,
		&hf_json_3gpp_suppfeat_npcf_sm_64_exposuretoeas,
		NULL
	};
	proto_tree_add_bitmask_list_value(sub_tree, suppfeat_tvb, offset_reverse, 1, json_3gpp_suppfeat_npcf_sm_list_16, g_ascii_xdigit_value(hex_ascii[offset_reverse]));
	offset_reverse--;

	if (offset_reverse == -1) {
		return;
	}

	static int* const json_3gpp_suppfeat_npcf_sm_list_17[] = {
		&hf_json_3gpp_suppfeat_npcf_sm_65_simultconnectivity,
		&hf_json_3gpp_suppfeat_npcf_sm_66_sgwrest,
		&hf_json_3gpp_suppfeat_npcf_sm_67_releasetoreactivate,
		&hf_json_3gpp_suppfeat_npcf_sm_68_easdiscovery,
		NULL
	};
	proto_tree_add_bitmask_list_value(sub_tree, suppfeat_tvb, offset_reverse, 1, json_3gpp_suppfeat_npcf_sm_list_17, g_ascii_xdigit_value(hex_ascii[offset_reverse]));
	offset_reverse--;

	if (offset_reverse == -1) {
		return;
	}

	static int* const json_3gpp_suppfeat_npcf_sm_list_18[] = {
		&hf_json_3gpp_suppfeat_npcf_sm_69_accnetchargid_string,
		NULL
	};

	proto_tree_add_bitmask_list_value(sub_tree, suppfeat_tvb, offset_reverse, 1, json_3gpp_suppfeat_npcf_sm_list_18, g_ascii_xdigit_value(hex_ascii[offset_reverse]));
	offset_reverse--;

	if (offset_reverse == -1) {
		return;
	}

	if (offset_reverse > -1) {
		proto_tree_add_format_text(sub_tree, suppfeat_tvb, 0, (offset_reverse - len));
	}
}

static void
dissect_3gpp_supportfeatures_npcf_ue_policy_control(tvbuff_t* suppfeat_tvb, proto_tree* sub_tree, packet_info* pinfo _U_, int offset _U_, int len, uint8_t *hex_ascii)
{
	int offset_reverse = len - 1;

	/* TS 29.525 ch5.8 Feature negotiation */

	static int * const json_3gpp_suppfeat_npcf_ue_list_1[] = {
		&hf_json_3gpp_suppfeat_npcf_ue_1_pendingtransaction,
		&hf_json_3gpp_suppfeat_npcf_ue_2_plmnchange,
		&hf_json_3gpp_suppfeat_npcf_ue_3_connectivitystatechange,
		&hf_json_3gpp_suppfeat_npcf_ue_4_v2x,
		NULL
	};
	proto_tree_add_bitmask_list_value(sub_tree, suppfeat_tvb, offset_reverse, 1, json_3gpp_suppfeat_npcf_ue_list_1, g_ascii_xdigit_value(hex_ascii[offset_reverse]));
	offset_reverse--;

	if (offset_reverse == -1) {
		return;
	}

	static int * const json_3gpp_suppfeat_npcf_ue_list_2[] = {
		&hf_json_3gpp_suppfeat_npcf_ue_5_groupidlistchange,
		&hf_json_3gpp_suppfeat_npcf_ue_6_immediatereport,
		&hf_json_3gpp_suppfeat_npcf_ue_7_errorresponse,
		&hf_json_3gpp_suppfeat_npcf_ue_8_es3xx,
		NULL
	};
	proto_tree_add_bitmask_list_value(sub_tree, suppfeat_tvb, offset_reverse, 1, json_3gpp_suppfeat_npcf_ue_list_2, g_ascii_xdigit_value(hex_ascii[offset_reverse]));
	offset_reverse--;

	if (offset_reverse == -1) {
		return;
	}

	static int * const json_3gpp_suppfeat_npcf_ue_list_3[] = {
		&hf_json_3gpp_suppfeat_npcf_ue_9_prose,
		NULL
	};
	proto_tree_add_bitmask_list_value(sub_tree, suppfeat_tvb, offset_reverse, 1, json_3gpp_suppfeat_npcf_ue_list_3, g_ascii_xdigit_value(hex_ascii[offset_reverse]));
	offset_reverse--;

	if (offset_reverse == -1) {
		return;
	}

	if (offset_reverse > -1) {
		proto_tree_add_format_text(sub_tree, suppfeat_tvb, 0, (offset_reverse - len));
	}

}

static void
dissect_3gpp_supportfeatures_nsmf_pdu_session(tvbuff_t* suppfeat_tvb, proto_tree* sub_tree, packet_info* pinfo _U_, int offset _U_, int len, uint8_t *hex_ascii)
{
	int offset_reverse = len - 1;

	/* TS 29.502 ch6.1.8 Feature negotiation */

	static int * const json_3gpp_suppfeat_nsmf_pdusession_list_1[] = {
		&hf_json_3gpp_suppfeat_nsmf_pdusession_1_ciot,
		&hf_json_3gpp_suppfeat_nsmf_pdusession_2_mapdu,
		&hf_json_3gpp_suppfeat_nsmf_pdusession_3_dtssa,
		&hf_json_3gpp_suppfeat_nsmf_pdusession_4_carpt,
		NULL
	};
	proto_tree_add_bitmask_list_value(sub_tree, suppfeat_tvb, offset_reverse, 1, json_3gpp_suppfeat_nsmf_pdusession_list_1, g_ascii_xdigit_value(hex_ascii[offset_reverse]));
	offset_reverse--;

	if (offset_reverse == -1) {
		return;
	}

	static int * const json_3gpp_suppfeat_nsmf_pdusession_list_2[] = {
		&hf_json_3gpp_suppfeat_nsmf_pdusession_5_ctxtr,
		&hf_json_3gpp_suppfeat_nsmf_pdusession_6_vqos,
		&hf_json_3gpp_suppfeat_nsmf_pdusession_7_hofail,
		&hf_json_3gpp_suppfeat_nsmf_pdusession_8_es3xx,
		NULL
	};
	proto_tree_add_bitmask_list_value(sub_tree, suppfeat_tvb, offset_reverse, 1, json_3gpp_suppfeat_nsmf_pdusession_list_2, g_ascii_xdigit_value(hex_ascii[offset_reverse]));
	offset_reverse--;

	if (offset_reverse == -1) {
		return;
	}

	static int * const json_3gpp_suppfeat_nsmf_pdusession_list_3[] = {
		&hf_json_3gpp_suppfeat_nsmf_pdusession_9_dce2er,
		&hf_json_3gpp_suppfeat_nsmf_pdusession_10_aasn,
		&hf_json_3gpp_suppfeat_nsmf_pdusession_11_enedge,
		&hf_json_3gpp_suppfeat_nsmf_pdusession_12_scpbu,
		NULL
	};
	proto_tree_add_bitmask_list_value(sub_tree, suppfeat_tvb, offset_reverse, 1, json_3gpp_suppfeat_nsmf_pdusession_list_3, g_ascii_xdigit_value(hex_ascii[offset_reverse]));
	offset_reverse--;

	if (offset_reverse == -1) {
		return;
	}

	static int * const json_3gpp_suppfeat_nsmf_pdusession_list_4[] = {
		&hf_json_3gpp_suppfeat_nsmf_pdusession_13_enpn,
		&hf_json_3gpp_suppfeat_nsmf_pdusession_14_spae,
		&hf_json_3gpp_suppfeat_nsmf_pdusession_15_5gsat,
		&hf_json_3gpp_suppfeat_nsmf_pdusession_16_upipe,
		NULL
	};
	proto_tree_add_bitmask_list_value(sub_tree, suppfeat_tvb, offset_reverse, 1, json_3gpp_suppfeat_nsmf_pdusession_list_4, g_ascii_xdigit_value(hex_ascii[offset_reverse]));
	offset_reverse--;

	if (offset_reverse == -1) {
		return;
	}

	static int * const json_3gpp_suppfeat_nsmf_pdusession_list_5[] = {
		&hf_json_3gpp_suppfeat_nsmf_pdusession_17_biumr,
		&hf_json_3gpp_suppfeat_nsmf_pdusession_18_acscr,
		&hf_json_3gpp_suppfeat_nsmf_pdusession_19_psetr,
		&hf_json_3gpp_suppfeat_nsmf_pdusession_20_dlset,
		NULL
	};
	proto_tree_add_bitmask_list_value(sub_tree, suppfeat_tvb, offset_reverse, 1, json_3gpp_suppfeat_nsmf_pdusession_list_5, g_ascii_xdigit_value(hex_ascii[offset_reverse]));
	offset_reverse--;

	if (offset_reverse == -1) {
		return;
	}

	static int * const json_3gpp_suppfeat_nsmf_pdusession_list_6[] = {
		&hf_json_3gpp_suppfeat_nsmf_pdusession_21_n9fsc,
		NULL
	};
	proto_tree_add_bitmask_list_value(sub_tree, suppfeat_tvb, offset_reverse, 1, json_3gpp_suppfeat_nsmf_pdusession_list_6, g_ascii_xdigit_value(hex_ascii[offset_reverse]));
	offset_reverse--;

	if (offset_reverse == -1) {
		return;
	}

	if (offset_reverse > -1) {
		proto_tree_add_format_text(sub_tree, suppfeat_tvb, 0, (offset_reverse - len));
	}
}

static void
dissect_3gpp_supportfeatures_nudm_sdm(tvbuff_t* suppfeat_tvb, proto_tree* sub_tree, packet_info* pinfo _U_, int offset _U_, int len, uint8_t *hex_ascii)
{
	int offset_reverse = len - 1;

	/* TS 29.503 ch6.1.8 Feature negotiation */

	static int * const json_3gpp_suppfeat_nudm_sdm_list_1[] = {
		&hf_json_3gpp_suppfeat_nudm_sdm_1_shareddata,
		&hf_json_3gpp_suppfeat_nudm_sdm_2_immediatereport,
		&hf_json_3gpp_suppfeat_nudm_sdm_3_patchreport,
		&hf_json_3gpp_suppfeat_nudm_sdm_4_nssaa,
		NULL
	};
	proto_tree_add_bitmask_list_value(sub_tree, suppfeat_tvb, offset_reverse, 1, json_3gpp_suppfeat_nudm_sdm_list_1, g_ascii_xdigit_value(hex_ascii[offset_reverse]));
	offset_reverse--;

	if (offset_reverse == -1) {
		return;
	}

	static int * const json_3gpp_suppfeat_nudm_sdm_list_2[] = {
		&hf_json_3gpp_suppfeat_nudm_sdm_5_cagfeature,
		&hf_json_3gpp_suppfeat_nudm_sdm_6_shareddatatreatment,
		&hf_json_3gpp_suppfeat_nudm_sdm_7_sortransparentsupport,
		&hf_json_3gpp_suppfeat_nudm_sdm_8_nsac,
		NULL
	};
	proto_tree_add_bitmask_list_value(sub_tree, suppfeat_tvb, offset_reverse, 1, json_3gpp_suppfeat_nudm_sdm_list_2, g_ascii_xdigit_value(hex_ascii[offset_reverse]));
	offset_reverse--;

	if (offset_reverse == -1) {
		return;
	}

	static int * const json_3gpp_suppfeat_nudm_sdm_list_3[] = {
		&hf_json_3gpp_suppfeat_nudm_sdm_9_sharedsmsubsdata,
		&hf_json_3gpp_suppfeat_nudm_sdm_10_ena,
		&hf_json_3gpp_suppfeat_nudm_sdm_11_nssrg,
		&hf_json_3gpp_suppfeat_nudm_sdm_12_uputransparentsupport,
		NULL
	};
	proto_tree_add_bitmask_list_value(sub_tree, suppfeat_tvb, offset_reverse, 1, json_3gpp_suppfeat_nudm_sdm_list_3, g_ascii_xdigit_value(hex_ascii[offset_reverse]));
	offset_reverse--;

	if (offset_reverse == -1) {
		return;
	}

	static int * const json_3gpp_suppfeat_nudm_sdm_list_4[] = {
		&hf_json_3gpp_suppfeat_nudm_sdm_13_limitedsubscriptions,
		&hf_json_3gpp_suppfeat_nudm_sdm_14_snpn_id,
		&hf_json_3gpp_suppfeat_nudm_sdm_15_ueconsmfdatasubfilter,
		&hf_json_3gpp_suppfeat_nudm_sdm_16_tempslicesupport,
		NULL
	};
	proto_tree_add_bitmask_list_value(sub_tree, suppfeat_tvb, offset_reverse, 1, json_3gpp_suppfeat_nudm_sdm_list_4, g_ascii_xdigit_value(hex_ascii[offset_reverse]));
	offset_reverse--;

	if (offset_reverse == -1) {
		return;
	}

	static int * const json_3gpp_suppfeat_nudm_sdm_list_5[] = {
		&hf_json_3gpp_suppfeat_nudm_sdm_17_expectedbehaviourmap,
		&hf_json_3gpp_suppfeat_nudm_sdm_18_shareddataext,
		&hf_json_3gpp_suppfeat_nudm_sdm_19_snpnidext,
		&hf_json_3gpp_suppfeat_nudm_sdm_20_caginfowithvalidityperiods,
		NULL
	};
	proto_tree_add_bitmask_list_value(sub_tree, suppfeat_tvb, offset_reverse, 1, json_3gpp_suppfeat_nudm_sdm_list_5, g_ascii_xdigit_value(hex_ascii[offset_reverse]));
	offset_reverse--;

	if (offset_reverse == -1) {
		return;
	}

	if (offset_reverse > -1) {
		proto_tree_add_format_text(sub_tree, suppfeat_tvb, 0, (offset_reverse - len));
	}
}

static void
dissect_3gpp_supportfeatures_nudm_uecm(tvbuff_t* suppfeat_tvb, proto_tree* sub_tree, packet_info* pinfo _U_, int offset _U_, int len, uint8_t *hex_ascii)
{
	int offset_reverse = len - 1;

	/* TS 29.503 ch6.2.8 Feature negotiation */

	static int * const json_3gpp_suppfeat_nudm_uecm_list_1[] = {
		&hf_json_3gpp_suppfeat_nudm_uecm_1_shareddata,
		&hf_json_3gpp_suppfeat_nudm_uecm_2_patchreport,
		&hf_json_3gpp_suppfeat_nudm_uecm_3_shareddatatreatment,
		&hf_json_3gpp_suppfeat_nudm_uecm_4_cagfeature,
		NULL
	};
	proto_tree_add_bitmask_list_value(sub_tree, suppfeat_tvb, offset_reverse, 1, json_3gpp_suppfeat_nudm_uecm_list_1, g_ascii_xdigit_value(hex_ascii[offset_reverse]));
	offset_reverse--;

	if (offset_reverse == -1) {
		return;
	}

	static int * const json_3gpp_suppfeat_nudm_uecm_list_2[] = {
		&hf_json_3gpp_suppfeat_nudm_uecm_5_deregistrationresponsebody,
		NULL
	};
	proto_tree_add_bitmask_list_value(sub_tree, suppfeat_tvb, offset_reverse, 1, json_3gpp_suppfeat_nudm_uecm_list_2, g_ascii_xdigit_value(hex_ascii[offset_reverse]));
	offset_reverse--;

	if (offset_reverse == -1) {
		return;
	}

	if (offset_reverse > -1) {
		proto_tree_add_format_text(sub_tree, suppfeat_tvb, 0, (offset_reverse - len));
	}
}

static void
dissect_3gpp_supportfeatures_nudm_ee(tvbuff_t* suppfeat_tvb, proto_tree* sub_tree, packet_info* pinfo _U_, int offset _U_, int len, uint8_t *hex_ascii)
{
	int offset_reverse = len - 1;

	/* TS 29.503 ch6.4.8 Feature negotiation */

	static int * const json_3gpp_suppfeat_nudm_ee_list_1[] = {
		&hf_json_3gpp_suppfeat_nudm_ee_1_patchreport,
		&hf_json_3gpp_suppfeat_nudm_ee_2_enena,
		&hf_json_3gpp_suppfeat_nudm_ee_3_dgem,
		&hf_json_3gpp_suppfeat_nudm_ee_4_iersr,
		NULL
	};
	proto_tree_add_bitmask_list_value(sub_tree, suppfeat_tvb, offset_reverse, 1, json_3gpp_suppfeat_nudm_ee_list_1, g_ascii_xdigit_value(hex_ascii[offset_reverse]));
	offset_reverse--;

	if (offset_reverse == -1) {
		return;
	}

	static int * const json_3gpp_suppfeat_nudm_ee_list_2[] = {
		&hf_json_3gpp_suppfeat_nudm_ee_5_enaph3,
		NULL
	};
	proto_tree_add_bitmask_list_value(sub_tree, suppfeat_tvb, offset_reverse, 1, json_3gpp_suppfeat_nudm_ee_list_2, g_ascii_xdigit_value(hex_ascii[offset_reverse]));
	offset_reverse--;

	if (offset_reverse == -1) {
		return;
	}

	if (offset_reverse > -1) {
		proto_tree_add_format_text(sub_tree, suppfeat_tvb, 0, (offset_reverse - len));
	}
}

static void
dissect_3gpp_supportfeatures_nudm_pp(tvbuff_t* suppfeat_tvb, proto_tree* sub_tree, packet_info* pinfo _U_, int offset _U_, int len, uint8_t *hex_ascii)
{
	int offset_reverse = len - 1;

	/* TS 29.503 ch6.5.8 Feature negotiation */

	static int * const json_3gpp_suppfeat_nudm_pp_list_1[] = {
		&hf_json_3gpp_suppfeat_nudm_pp_1_patchreport,
		&hf_json_3gpp_suppfeat_nudm_pp_2_expectedbehaviourmap,
		&hf_json_3gpp_suppfeat_nudm_pp_3_membersdata,
		NULL
	};
	proto_tree_add_bitmask_list_value(sub_tree, suppfeat_tvb, offset_reverse, 1, json_3gpp_suppfeat_nudm_pp_list_1, g_ascii_xdigit_value(hex_ascii[offset_reverse]));
	offset_reverse--;

	if (offset_reverse == -1) {
		return;
	}

	if (offset_reverse > -1) {
		proto_tree_add_format_text(sub_tree, suppfeat_tvb, 0, (offset_reverse - len));
	}
}

static void
dissect_3gpp_supportfeatures(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo, int offset, int len, const char* key_str _U_)
{
	const char *path = NULL;

	/* TS 29.571 ch5.2.2
	 * A string used to indicate the features supported by an API that is used as defined in clause 6.6 in 3GPP TS 29.500 [25].
	 * The string shall contain a bitmask indicating supported features in hexadecimal representation:
	 * Each character in the string shall take a value of "0" to "9", "a" to "f" or "A" to "F" and
	 * shall represent the support of 4 features as described in table 5.2.2-3.
	 * The most significant character representing the highest-numbered features shall appear first in the string,
	 * and the character representing features 1 to 4 shall appear last in the string.
	 * The list of features and their numbering (starting with 1) are defined separately for each API.
	 * If the string contains a lower number of characters than there are defined features for an API,
	 * all features that would be represented by characters that are not present in the string are not supported.
	 */

	/* Expect to have :path from HTTP2 here, if not return */
	if (proto_is_frame_protocol(pinfo->layers, "http2")) {
		path = http2_get_header_value(pinfo, HTTP2_HEADER_PATH, false);
		if (!path) {
			path = http2_get_header_value(pinfo, HTTP2_HEADER_PATH, true);
		}
	} else if (proto_is_frame_protocol(pinfo->layers, "http")) {
		/* 3GPP TS 29.500 says the service based interfaces use HTTP/2,
		 * but that doesn't stop implementations like OAI from using
		 * HTTP/1.1 with a 2.0 version string.
		 */
		http_req_res_t* curr_req_res = (http_req_res_t*)p_get_proto_data(wmem_file_scope(), pinfo, proto_http, HTTP_PROTO_DATA_REQRES);
		if (curr_req_res) {
			path = curr_req_res->request_uri;
		}
	}
	if (!path) {
		return;
	}

	proto_item* ti;
	proto_tree* sub_tree;
	tvbuff_t   *suppfeat_tvb;

	ti = proto_tree_add_item(tree, hf_json_3gpp_suppfeat, tvb, offset, len, ENC_ASCII);
	if (len <= 0) {
		return;
	}
	sub_tree = proto_item_add_subtree(ti, ett_json_3gpp_data);
	suppfeat_tvb = tvb_new_subset_length(tvb, offset, len);

	/* Read in the HEX in ASCII form and validate it's 0-9,A-F */
	uint8_t *hex_ascii = tvb_memdup(pinfo->pool, tvb, offset, len);
	for (int i = 0; i < len; i++) {
		char c = hex_ascii[i];
		if (!g_ascii_isxdigit(c)) {
			proto_tree_add_expert_format_remaining(sub_tree, pinfo, &ei_json_3gpp_encoding_error, suppfeat_tvb, 0, "Invalid char pos=%d value=%02x", i, c);
			return;
		}
	}

	if (strcmp(path, NAF_EVENTEXPOSTURE) == 0) {
		/* TS 29.517 ch5.8 Feature negotiation */
		dissect_3gpp_supportfeatures_naf_eventexposure(suppfeat_tvb, sub_tree, pinfo, offset, len, hex_ascii);

	} else if (strcmp(path, NLMF_BROADCAST) == 0) {
		/* TS 29.572 ch6.2.9 Feature negotiation */
		dissect_3gpp_supportfeatures_nlmf_broadcast(suppfeat_tvb, sub_tree, pinfo, offset, len, hex_ascii);

	} else if (strcmp(path, NLMF_LOC) == 0) {
		/* TS 29.572 ch6.1.9 Feature negotiation */
		dissect_3gpp_supportfeatures_nlmf_loc(suppfeat_tvb, sub_tree, pinfo, offset, len, hex_ascii);

	} else if (strcmp(path, NPCF_AM_POLICY_CONTROL) == 0) {
		/* TS 29.507 ch5.8 Feature negotiation */
		dissect_3gpp_supportfeatures_npcf_am_policy_control(suppfeat_tvb, sub_tree, pinfo, offset, len, hex_ascii);

	} else if (strcmp(path, NPCF_SM_POLICY_CONTROL) == 0) {
		/* TS 29.512 ch5.8 Feature negotiation */
		dissect_3gpp_supportfeatures_npcf_sm_policy_control(suppfeat_tvb, sub_tree, pinfo, offset, len, hex_ascii);

	} else if (strcmp(path, NPCF_UE_POLICY_CONTROL) == 0) {
		/* TS 29.525 ch5.8 Feature negotiation */
		dissect_3gpp_supportfeatures_npcf_ue_policy_control(suppfeat_tvb, sub_tree, pinfo, offset, len, hex_ascii);

	} else if (strncmp(path, NSMF_PDU_SESSION, 20) == 0) {
		/* TS 29.502 ch6.1.8 Feature negotiation */
		dissect_3gpp_supportfeatures_nsmf_pdu_session(suppfeat_tvb, sub_tree, pinfo, offset, len, hex_ascii);

	} else if (strcmp(path, NUDM_SDM) == 0) {
		/* TS 29.503 ch6.1.8 Feature negotiation */
		dissect_3gpp_supportfeatures_nudm_sdm(suppfeat_tvb, sub_tree, pinfo, offset, len, hex_ascii);

	} else if (strcmp(path, NUDM_EUCM) == 0) {
		/* TS 29.503 ch6.2.8 Feature negotiation */
		dissect_3gpp_supportfeatures_nudm_uecm(suppfeat_tvb, sub_tree, pinfo, offset, len, hex_ascii);

	} else if (strcmp(path, NUDM_EE) == 0) {
		/* TS 29.503 ch6.4.8 Feature negotiation */
		dissect_3gpp_supportfeatures_nudm_ee(suppfeat_tvb, sub_tree, pinfo, offset, len, hex_ascii);

	} else if (strcmp(path, NUDM_PP) == 0) {
		/* TS 29.503 ch6.5.8 Feature negotiation */
		dissect_3gpp_supportfeatures_nudm_pp(suppfeat_tvb, sub_tree, pinfo, offset, len, hex_ascii);

	} else {
		proto_tree_add_expert_remaining(tree, pinfo, &ei_json_3gpp_data_not_decoded, tvb, offset);
	}

	return;
}

static void
dissect_3gpp_supi(tvbuff_t* tvb, proto_tree* tree, packet_info* pinfo, int offset, int len, const char* key_str _U_)
{
	tvbuff_t   *supi_tvb;
	GMatchInfo *match_info;
	static GRegex *regex = NULL;
	char *matched_imsi = NULL;

	if (len <= 0) {
		return;
	}

	supi_tvb = tvb_new_subset_length(tvb, offset, len);

	/* 3GPP TS 29.571
	 * String identifying a Supi that shall contain either an IMSI, a network specific identifier,
	 * a Global Cable Identifier (GCI) or a Global Line Identifier (GLI) as specified in clause 2.2A of 3GPP TS 23.003.
	 *
	 * We are interested in IMSI and will be formatted as follows:
	 *   Pattern: '^imsi-[0-9]{5,15}$'
	 */
	if (regex == NULL) {
		regex = g_regex_new (
			"^imsi-([0-9]{5,15})$",
			G_REGEX_CASELESS | G_REGEX_FIRSTLINE, 0, NULL);
	}

	char *supi_str = (char*)tvb_get_string_enc(pinfo->pool, supi_tvb, 0, tvb_captured_length(supi_tvb), ENC_UTF_8);
	g_regex_match(regex, supi_str, 0, &match_info);

	if (g_match_info_matches(match_info)) {
		matched_imsi = g_match_info_fetch(match_info, 1); //will be empty string if imsi is not in supi
		if (matched_imsi && (strcmp(matched_imsi, "") != 0)) {
			add_assoc_imsi_item(supi_tvb, tree, matched_imsi);
			/* Add Associate IMSI to HTTP2 stream */
			if (proto_is_frame_protocol(pinfo->layers, "http2")) {
				http2_set_stream_imsi(pinfo, matched_imsi);
			}
		}
		g_free(matched_imsi);
	}
	g_match_info_free(match_info);

	return;
}

static void
dissect_3gpp_notifyuri(tvbuff_t* tvb, proto_tree* tree _U_, packet_info* pinfo, int offset, int len, const char* key_str _U_)
{
	tvbuff_t   *notifyuri_tvb;
	GMatchInfo *match_info;
	static GRegex *regex = NULL;
	char *matched_notifyuri = NULL;
	const char *imsi = NULL;

	if (len <= 0) {
		return;
	}

	notifyuri_tvb = tvb_new_subset_length(tvb, offset, len);

	/* NotifyUri is generally just uri does not have any specific format */
	if (regex == NULL) {
		regex = g_regex_new (
		        "^(?:https?:\\/\\/[^/]+)?(\\/.*)$", //Matches with uris except root
			G_REGEX_CASELESS | G_REGEX_FIRSTLINE, 0, NULL);
	}

	char *notifyuri_str = (char*)tvb_get_string_enc(pinfo->pool, notifyuri_tvb, 0, tvb_captured_length(notifyuri_tvb), ENC_UTF_8);
	g_regex_match(regex, notifyuri_str, 0, &match_info);

	if (g_match_info_matches(match_info)) {
		matched_notifyuri = g_match_info_fetch(match_info, 1); //will be empty string if notify uri does not contain http or https
		if (matched_notifyuri && (strcmp(matched_notifyuri, "") != 0)) {
			if (proto_is_frame_protocol(pinfo->layers, "http2")) {
				imsi = http2_get_stream_imsi(pinfo);
				if(imsi) {
					http2_add_notifyuri_imsi(matched_notifyuri, imsi);
				}
			}
		}
		g_free(matched_notifyuri);
	}
	g_match_info_free(match_info);

	return;
}

static void
register_static_headers(void) {

	char* header_name;

	/* Here hf[x].hfinfo.name is a header method which is used as key
	 * for matching ids while processing HTTP2 packets */
	static hf_register_info hf[] = {
		{
			&hf_json_3gpp_ueepspdnconnection,
			{"ueEpsPdnConnection", "json.3gpp.ueepspdnconnection",
				FT_STRING, BASE_NONE, NULL, 0x0,
				NULL, HFILL}
		},
		{
			&hf_json_3gpp_bearerlevelqos,
			{"bearerLevelQoS", "json.3gpp.bearerlevelqos",
				FT_STRING, BASE_NONE, NULL, 0x0,
				NULL, HFILL}
		},
		{
			&hf_json_3gpp_epsbearersetup,
			{"epsBearerSetup", "json.3gpp.epsbearersetup",
				FT_STRING, BASE_NONE, NULL, 0x0,
				NULL, HFILL}
		},
		{
			&hf_json_3gpp_forwardingbearercontexts,
			{"forwardingBearerContexts", "json.3gpp.forwardingbearercontexts",
				FT_STRING, BASE_NONE, NULL, 0x0,
				NULL, HFILL}
		},
		{
			&hf_json_3gpp_forwardingfteid,
			{"forwardingFTeid", "json.3gpp.forwardingfteid",
				FT_STRING, BASE_NONE, NULL, 0x0,
				NULL, HFILL}
		},
		{
			&hf_json_3gpp_pgwnodename,
			{"pgwNodeName", "json.3gpp.pgwnodename",
				FT_STRING, BASE_NONE, NULL, 0x0,
				NULL, HFILL}
		},
		{
			&hf_json_3gpp_pgws8cfteid,
			{"pgwS8cFteid", "json.3gpp.pgws8cfteid",
				FT_STRING, BASE_NONE, NULL, 0x0,
				NULL, HFILL}
		},
		{
			&hf_json_3gpp_pgws8ufteid,
			{"pgwS8uFteid", "json.3gpp.pgws8ufteid",
				FT_STRING, BASE_NONE, NULL, 0x0,
				NULL, HFILL}
		},
		{
			&hf_json_3gpp_qosrules,
			{"qosRules", "json.3gpp.qosrules",
				FT_STRING, BASE_NONE, NULL, 0x0,
				NULL, HFILL}
		},
		{
			&hf_json_3gpp_qosflowdescription,
			{"qosFlowDescription", "json.3gpp.qosflowdescription",
				FT_STRING, BASE_NONE, NULL, 0x0,
				NULL, HFILL}
		},
		{
			&hf_json_3gpp_suppFeat,
			{"suppFeat", "json.3gpp.suppFeat",
				FT_STRING, BASE_NONE, NULL, 0x0,
				NULL, HFILL}
		},
		{
			&hf_json_3gpp_supportedFeatures,
			{"supportedFeatures", "json.3gpp.supportedFeatures",
				FT_STRING, BASE_NONE, NULL, 0x0,
				NULL, HFILL}
		},
		{
			&hf_json_3gpp_supi,
			{"supi", "json.3gpp.supi",
				FT_STRING, BASE_NONE, NULL, 0x0,
				NULL, HFILL}
		},
		{
			&hf_json_3gpp_subscriberIdentifier,
			{"subscriberIdentifier", "json.3gpp.subscriberIdentifier",
				FT_STRING, BASE_NONE, NULL, 0x0,
				NULL, HFILL}
		},
		{
			&hf_json_3gpp_notifyuri,
			{"notifyUri", "json.3gpp.notifyUri",
				FT_STRING, BASE_NONE, NULL, 0x0,
				NULL, HFILL}
		},
		{
			&hf_json_3gpp_notificationuri,
			{"notificationUri", "json.3gpp.notificationUri",
				FT_STRING, BASE_NONE, NULL, 0x0,
				NULL, HFILL}
		},
		{
			&hf_json_3gpp_amfStatusUri,
			{"amfStatusUri", "json.3gpp.amfStatusUri",
				FT_STRING, BASE_NONE, NULL, 0x0,
				NULL, HFILL}
		},
		{
			&hf_json_3gpp_n1NotifyCallbackUri,
			{"n1NotifyCallbackUri", "json.3gpp.n1NotifyCallbackUri",
				FT_STRING, BASE_NONE, NULL, 0x0,
				NULL, HFILL}
		},
		{
			&hf_json_3gpp_n2NotifyCallbackUri,
			{"n2NotifyCallbackUri", "json.3gpp.n2NotifyCallbackUri",
				FT_STRING, BASE_NONE, NULL, 0x0,
				NULL, HFILL}
		},
		{
			&hf_json_3gpp_n1n2FailureTxfNotifURI,
			{"n1n2FailureTxfNotifURI", "json.3gpp.n1n2FailureTxfNotifURI",
				FT_STRING, BASE_NONE, NULL, 0x0,
				NULL, HFILL}
		},
		{
			&hf_json_3gpp_ismfPduSessionUri,
			{"ismfPduSessionUri", "json.3gpp.ismfPduSessionUri",
				FT_STRING, BASE_NONE, NULL, 0x0,
				NULL, HFILL}
		},
		{
			&hf_json_3gpp_hsmfPduSessionUri,
			{"hsmfPduSessionUri", "json.3gpp.hsmfPduSessionUri",
				FT_STRING, BASE_NONE, NULL, 0x0,
				NULL, HFILL}
		},
		{
			&hf_json_3gpp_vsmfPduSessionUri,
			{"vsmfPduSessionUri", "json.3gpp.vsmfPduSessionUri",
				FT_STRING, BASE_NONE, NULL, 0x0,
				NULL, HFILL}
		},
		{
			&hf_json_3gpp_callbackReference,
			{"callbackReference", "json.3gpp.callbackReference",
				FT_STRING, BASE_NONE, NULL, 0x0,
				NULL, HFILL}
		},
		{
			&hf_json_3gpp_pcscfRestorationCallbackUri,
			{"pcscfRestorationCallbackUri", "json.3gpp.pcscfRestorationCallbackUri",
				FT_STRING, BASE_NONE, NULL, 0x0,
				NULL, HFILL}
		},
		{
			&hf_json_3gpp_deregCallbackUri,
			{"deregCallbackUri", "json.3gpp.deregCallbackUri",
				FT_STRING, BASE_NONE, NULL, 0x0,
				NULL, HFILL}
		},
		{
			&hf_json_3gpp_staleCheckCallbackUri,
			{"staleCheckCallbackUri", "json.3gpp.staleCheckCallbackUri",
				FT_STRING, BASE_NONE, NULL, 0x0,
				NULL, HFILL}
		}
	};

	/* List of decoding functions the index matches the HF */
	static void(* const json_decode_fn[])(tvbuff_t * tvb, proto_tree * tree, packet_info * pinfo, int offset, int len, const char* key_str) = {
		dissect_base64decoded_eps_ie,   /* ueEpsPdnConnection */
		dissect_base64decoded_eps_ie,   /* bearerLevelQoS */
		dissect_base64decoded_eps_ie,   /* epsBearerSetup */
		dissect_base64decoded_eps_ie,   /* forwardingBearerContexts */
		dissect_base64decoded_eps_ie,   /* forwardingFTeid */
		dissect_base64decoded_eps_ie,   /* pgwNodeName */
		dissect_base64decoded_eps_ie,   /* pgwS8cFteid */
		dissect_base64decoded_eps_ie,   /* pgwS8uFteid */

		dissect_base64decoded_nas5g_ie, /* qosRules */
		dissect_base64decoded_nas5g_ie, /* qosFlowDescription */

		dissect_3gpp_supportfeatures,   /* suppFeat */
		dissect_3gpp_supportfeatures,   /* supportedFeatures */

		dissect_3gpp_supi,			/* supi */
		dissect_3gpp_supi,			/* subscriberIdentifier */

		dissect_3gpp_notifyuri,		/* NotifyUri */
		dissect_3gpp_notifyuri,		/* notificationUri */
		dissect_3gpp_notifyuri,		/* amfStatusUri */
		dissect_3gpp_notifyuri,		/* n1NotifyCallbackUri */
		dissect_3gpp_notifyuri,		/* n2NotifyCallbackUri */
		dissect_3gpp_notifyuri,		/* n1n2FailureTxfNotifURI */
		dissect_3gpp_notifyuri,		/* ismfPduSessionUri */
		dissect_3gpp_notifyuri,		/* hsmfPduSessionUri */
		dissect_3gpp_notifyuri,		/* vsmfPduSessionUri */
		dissect_3gpp_notifyuri,		/* callbackReference */
		dissect_3gpp_notifyuri,		/* pcscfRestorationCallbackUri */
		dissect_3gpp_notifyuri,		/* deregCallbackUri */
		dissect_3gpp_notifyuri,		/* staleCheckCallbackUri */

		NULL,   /* NONE */
	};

	/* Hfs with functions */
	for (unsigned i = 0; i < G_N_ELEMENTS(hf); ++i) {
		header_name = g_strdup(hf[i].hfinfo.name);
		json_data_decoder_t* json_data_decoder_rec = g_new(json_data_decoder_t, 1);
		json_data_decoder_rec->hf_id = &hf[i].hfinfo.id;
		json_data_decoder_rec->json_data_decoder = json_decode_fn[i];
		g_hash_table_insert(json_header_fields_hash, header_name, json_data_decoder_rec);
	}

	proto_register_field_array(proto_json_3gpp, hf, G_N_ELEMENTS(hf));
}

void
proto_register_json_3gpp(void)
{
	static hf_register_info hf[] = {

		/* 3GPP content */
		{ &hf_json_3gpp_binary_data,
			{ "Binary data", "json.binary_data",
			  FT_BYTES, BASE_NONE, NULL, 0x00,
			  "JSON binary data", HFILL }
		},
		{ &hf_json_3gpp_suppfeat,
			{ "Supported Features", "json.3gpp.suppfeat",
			  FT_STRING, BASE_NONE, NULL, 0x0,
			  NULL, HFILL }
		},



		{ &hf_json_3gpp_suppfeat_naf_eventexposure_1_serviceexperience,
			{ "ServiceExperience", "json.3gpp.suppfeat.serviceexperience",
			FT_BOOLEAN, 4, NULL, 0x1,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_naf_eventexposure_2_uemobility,
			{ "UeMobility", "json.3gpp.suppfeat.uemobility",
			FT_BOOLEAN, 4, NULL, 0x2,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_naf_eventexposure_3_uecommunication,
			{ "UeCommunication", "json.3gpp.suppfeat.uecommunication",
			FT_BOOLEAN, 4, NULL, 0x4,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_naf_eventexposure_4_exceptions,
			{ "Exceptions", "json.3gpp.suppfeat.exceptions",
			FT_BOOLEAN, 4, NULL, 0x8,
			NULL, HFILL }
		},

		{ &hf_json_3gpp_suppfeat_naf_eventexposure_5_es3xx,
			{ "ES3XX", "json.3gpp.suppfeat.es3xx",
			FT_BOOLEAN, 4, NULL, 0x1,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_naf_eventexposure_6_enena,
			{ "EneNA", "json.3gpp.suppfeat.enena",
			FT_BOOLEAN, 4, NULL, 0x2,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_naf_eventexposure_7_userdatacongestion,
			{ "UserDataCongestion", "json.3gpp.suppfeat.userdatacongestion",
			FT_BOOLEAN, 4, NULL, 0x4,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_naf_eventexposure_8_performancedata,
			{ "PerformanceData", "json.3gpp.suppfeat.performancedata",
			FT_BOOLEAN, 4, NULL, 0x8,
			NULL, HFILL }
		},

		{ &hf_json_3gpp_suppfeat_naf_eventexposure_9_dispersion,
			{ "Dispersion", "json.3gpp.suppfeat.dispersion",
			FT_BOOLEAN, 4, NULL, 0x1,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_naf_eventexposure_10_collectivebehaviour,
			{ "CollectiveBehaviour", "json.3gpp.suppfeat.collectivebehaviour",
			FT_BOOLEAN, 4, NULL, 0x2,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_naf_eventexposure_11_serviceexperienceext,
			{ "ServiceExperienceExt", "json.3gpp.suppfeat.serviceexperienceext",
			FT_BOOLEAN, 4, NULL, 0x4,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_naf_eventexposure_12_msqoemetrics,
			{ "MSQoeMetrics", "json.3gpp.suppfeat.msqoemetrics",
			FT_BOOLEAN, 4, NULL, 0x8,
			NULL, HFILL }
		},

		{ &hf_json_3gpp_suppfeat_naf_eventexposure_13_msconsumption,
			{ "MSConsumption", "json.3gpp.suppfeat.msconsumption",
			FT_BOOLEAN, 4, NULL, 0x1,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_naf_eventexposure_14_msnetassinvocation,
			{ "MSNetAssInvocation", "json.3gpp.suppfeat.msnetassinvocation",
			FT_BOOLEAN, 4, NULL, 0x2,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_naf_eventexposure_15_msdynpolicyinvocation,
			{ "MSDynPolicyInvocation", "json.3gpp.suppfeat.msdynpolicyinvocation",
			FT_BOOLEAN, 4, NULL, 0x4,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_naf_eventexposure_16_msaccessactivity,
			{ "MSAccessActivity", "json.3gpp.suppfeat.msaccessactivity",
			FT_BOOLEAN, 4, NULL, 0x8,
			NULL, HFILL }
		},

		{ &hf_json_3gpp_suppfeat_naf_eventexposure_17_dataaccprofileid,
			{ "DataAccProfileId", "json.3gpp.suppfeat.dataaccprofileid",
			FT_BOOLEAN, 4, NULL, 0x1,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_naf_eventexposure_18_allapplications,
			{ "AllApplications", "json.3gpp.suppfeat.allapplications",
			FT_BOOLEAN, 4, NULL, 0x2,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_naf_eventexposure_19_gnssassistdata,
			{ "GNSSAssistData", "json.3gpp.suppfeat.gnssassistdata",
			FT_BOOLEAN, 4, NULL, 0x4,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_naf_eventexposure_20_performancedataext_aiml,
			{ "PerformanceDataExt_AIML", "json.3gpp.suppfeat.performancedataext_aiml",
			FT_BOOLEAN, 4, NULL, 0x8,
			NULL, HFILL }
		},

		{ &hf_json_3gpp_suppfeat_naf_eventexposure_21_uemobilityext_aiml,
			{ "UeMobilityExt_AIML", "json.3gpp.suppfeat.uemobilityext_aiml",
			FT_BOOLEAN, 4, NULL, 0x1,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_naf_eventexposure_22_enperformancedata,
			{ "EnPerformanceData", "json.3gpp.suppfeat.enperformancedata",
			FT_BOOLEAN, 4, NULL, 0x2,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_naf_eventexposure_23_uecommunicationext_ena,
			{ "UeCommunicationExt_eNA", "json.3gpp.suppfeat.uecommunicationext_ena",
			FT_BOOLEAN, 4, NULL, 0x4,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_naf_eventexposure_24_serviceexperienceext2_ena,
			{ "ServiceExperienceExt2_eNA", "json.3gpp.suppfeat.serviceexperienceext2_ena",
			FT_BOOLEAN, 4, NULL, 0x8,
			NULL, HFILL }
		},

		{ &hf_json_3gpp_suppfeat_naf_eventexposure_25_enhdatamgmt,
			{ "EnhDataMgmt", "json.3gpp.suppfeat.enhdatamgmt",
			FT_BOOLEAN, 4, NULL, 0x1,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_naf_eventexposure_26_exteventfilters,
			{ "ExtEventFilters", "json.3gpp.suppfeat.exteventfilters",
			FT_BOOLEAN, 4, NULL, 0x2,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_naf_eventexposure_27_datavoltransfertime,
			{ "DataVolTransferTime", "json.3gpp.suppfeat.datavoltransfertime",
			FT_BOOLEAN, 4, NULL, 0x4,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_naf_eventexposure_28_mseventexposure,
			{ "MSEventExposure", "json.3gpp.suppfeat.mseventexposure",
			FT_BOOLEAN, 4, NULL, 0x8,
			NULL, HFILL }
		},

		{ &hf_json_3gpp_suppfeat_naf_eventexposure_29_pereventrepreq,
			{ "PerEventRepReq", "json.3gpp.suppfeat.pereventrepreq",
			FT_BOOLEAN, 4, NULL, 0x1,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_naf_eventexposure_30_relativeproximity,
			{ "RelativeProximity", "json.3gpp.suppfeat.relativeproximity",
			FT_BOOLEAN, 4, NULL, 0x2,
			NULL, HFILL }
		},

		{ &hf_json_3gpp_suppfeat_nlmf_broadcast_1_es3xx,
			{ "ES3XX", "json.3gpp.suppfeat.es3xx",
			FT_BOOLEAN, 4, NULL, 0x1,
			NULL, HFILL }
		},

		{ &hf_json_3gpp_suppfeat_nlmf_loc_1_es3xx,
			{ "ES3XX", "json.3gpp.suppfeat.es3xx",
			FT_BOOLEAN, 4, NULL, 0x1,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_nlmf_loc_2_sat,
			{ "SAT", "json.3gpp.suppfeat.sat",
			FT_BOOLEAN, 4, NULL, 0x2,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_nlmf_loc_3_mutiqos,
			{ "MUTIQOS", "json.3gpp.suppfeat.mutiqos",
			FT_BOOLEAN, 4, NULL, 0x4,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_nlmf_loc_4_mbsr,
			{ "MBSR", "json.3gpp.suppfeat.mbsr",
			FT_BOOLEAN, 4, NULL, 0x8,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_nlmf_loc_5_ranging_sl,
			{ "Ranging SL", "json.3gpp.suppfeat.ranging_sl",
			FT_BOOLEAN, 4, NULL, 0x1,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_nlmf_loc_6_intres,
			{ "INTRES", "json.3gpp.suppfeat.intres",
			FT_BOOLEAN, 4, NULL, 0x2,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_nlmf_loc_7_cimlr,
			{ "CIMLR", "json.3gpp.suppfeat.cimlr",
			FT_BOOLEAN, 4, NULL, 0x4,
			NULL, HFILL }
		},

		{ &hf_json_3gpp_suppfeat_npcf_am_1_slicesupport,
			{ "SliceSupport", "json.3gpp.suppfeat.slicesupport",
			FT_BOOLEAN, 4, NULL, 0x1,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_am_2_pendingtransaction,
			{ "PendingTransaction", "json.3gpp.suppfeat.pendingtransaction",
			FT_BOOLEAN, 4, NULL, 0x2,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_am_3_ueambrauthorization,
			{ "UE-AMBR_Authorization", "json.3gpp.suppfeat.ueambrauthorization",
			FT_BOOLEAN, 4, NULL, 0x4,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_am_4_dnnreplacementcontrol,
			{ "DNNReplacementControl", "json.3gpp.suppfeat.dnnreplacementcontrol",
			FT_BOOLEAN, 4, NULL, 0x8,
			NULL, HFILL }
		},

		{ &hf_json_3gpp_suppfeat_npcf_am_5_multipleaccesstypes,
			{ "MultipleAccessTypes", "json.3gpp.suppfeat.multipleaccesstypes",
			FT_BOOLEAN, 4, NULL, 0x1,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_am_6_wirelinewirelessconvergence,
			{ "WirelineWirelessConvergence", "json.3gpp.suppfeat.wirelinewirelessconvergence",
			FT_BOOLEAN, 4, NULL, 0x2,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_am_7_immediatereport,
			{ "ImmediateReport", "json.3gpp.suppfeat.immediatereport",
			FT_BOOLEAN, 4, NULL, 0x4,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_am_8_es3xx,
			{ "ES3XX", "json.3gpp.suppfeat.es3xx",
			FT_BOOLEAN, 4, NULL, 0x8,
			NULL, HFILL }
		},

		{ &hf_json_3gpp_suppfeat_npcf_am_9_ueslicembrauthorization,
			{ "UE-Slice-MBR_Authorization", "json.3gpp.suppfeat.ueslicembrauthorization",
			FT_BOOLEAN, 4, NULL, 0x1,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_am_10_aminfluence,
			{ "AMInfluence", "json.3gpp.suppfeat.aminfluence",
			FT_BOOLEAN, 4, NULL, 0x2,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_am_11_enena,
			{ "EneNA", "json.3gpp.suppfeat.enena",
			FT_BOOLEAN, 4, NULL, 0x4,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_am_12_targetnssai,
			{ "TargetNSSAI", "json.3gpp.suppfeat.targetnssai",
			FT_BOOLEAN, 4, NULL, 0x8,
			NULL, HFILL }
		},

		{ &hf_json_3gpp_suppfeat_npcf_am_13_5gaccessstratumtime,
			{ "5GAccessStratumTime", "json.3gpp.suppfeat.5gaccessstratumtime",
			FT_BOOLEAN, 4, NULL, 0x1,
			NULL, HFILL }
		},

		{ &hf_json_3gpp_suppfeat_npcf_sm_1_tsc,
			{ "TSC", "json.3gpp.suppfeat.tsc",
			FT_BOOLEAN, 4, NULL, 0x1,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_sm_2_resshare,
			{ "ResShare", "json.3gpp.suppfeat.resshare",
			FT_BOOLEAN, 4, NULL, 0x2,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_sm_3_3gpppsdataoff,
			{ "3GPP-PS-Data-Off", "json.3gpp.suppfeat.3gpppsdataoff",
			FT_BOOLEAN, 4, NULL, 0x4,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_sm_4_adc,
			{ "ADC", "json.3gpp.suppfeat.adc",
			FT_BOOLEAN, 4, NULL, 0x8,
			NULL, HFILL }
		},

		{ &hf_json_3gpp_suppfeat_npcf_sm_5_umc,
			{ "UMC", "json.3gpp.suppfeat.umc",
			FT_BOOLEAN, 4, NULL, 0x1,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_sm_6_netloc,
			{ "NetLoc", "json.3gpp.suppfeat.netloc",
			FT_BOOLEAN, 4, NULL, 0x2,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_sm_7_rannascause,
			{ "RAN-NAS-Cause", "json.3gpp.suppfeat.rannascause",
			FT_BOOLEAN, 4, NULL, 0x4,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_sm_8_provafsignalflow,
			{ "ProvAFsignalFlow", "json.3gpp.suppfeat.provafsignalflow",
			FT_BOOLEAN, 4, NULL, 0x8,
			NULL, HFILL }
		},

		{ &hf_json_3gpp_suppfeat_npcf_sm_9_pcscfrestorationenhancement,
			{ "PCSCF-Restoration-Enhancement", "json.3gpp.suppfeat.pcscfrestorationenhancement",
			FT_BOOLEAN, 4, NULL, 0x1,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_sm_10_pra,
			{ "PRA", "json.3gpp.suppfeat.pra",
			FT_BOOLEAN, 4, NULL, 0x2,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_sm_11_ruleversioning,
			{ "RuleVersioning", "json.3gpp.suppfeat.ruleversioning",
			FT_BOOLEAN, 4, NULL, 0x4,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_sm_12_sponsoredconnectivity,
			{ "SponsoredConnectivity", "json.3gpp.suppfeat.sponsoredconnectivity",
			FT_BOOLEAN, 4, NULL, 0x8,
			NULL, HFILL }
		},

		{ &hf_json_3gpp_suppfeat_npcf_sm_13_ransupportinfo,
			{ "RAN-Support-Info", "json.3gpp.suppfeat.ransupportinfo",
			FT_BOOLEAN, 4, NULL, 0x1,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_sm_14_policyupdatewhenuesuspends,
			{ "PolicyUpdateWhenUESuspends", "json.3gpp.suppfeat.policyupdatewhenuesuspends",
			FT_BOOLEAN, 4, NULL, 0x2,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_sm_15_accesstypecondition,
			{ "AccessTypeCondition", "json.3gpp.suppfeat.accesstypecondition",
			FT_BOOLEAN, 4, NULL, 0x4,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_sm_16_multiipv6addrprefix,
			{ "MultiIpv6AddrPrefix", "json.3gpp.suppfeat.multiipv6addrprefix",
			FT_BOOLEAN, 4, NULL, 0x8,
			NULL, HFILL }
		},

		{ &hf_json_3gpp_suppfeat_npcf_sm_17_sessionruleerrorhandling,
			{ "SessionRuleErrorHandling", "json.3gpp.suppfeat.sessionruleerrorhandling",
			FT_BOOLEAN, 4, NULL, 0x1,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_sm_18_af_charging_identifier,
			{ "AF_Charging_Identifier", "json.3gpp.suppfeat.af_charging_identifier",
			FT_BOOLEAN, 4, NULL, 0x2,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_sm_19_atsss,
			{ "ATSSS", "json.3gpp.suppfeat.atsss",
			FT_BOOLEAN, 4, NULL, 0x4,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_sm_20_pendingtransaction,
			{ "PendingTransaction", "json.3gpp.suppfeat.pendingtransaction",
			FT_BOOLEAN, 4, NULL, 0x8,
			NULL, HFILL }
		},

		{ &hf_json_3gpp_suppfeat_npcf_sm_21_urllc,
			{ "URLLC", "json.3gpp.suppfeat.urllc",
			FT_BOOLEAN, 4, NULL, 0x1,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_sm_22_macaddressrange,
			{ "MacAddressRange", "json.3gpp.suppfeat.macaddressrange",
			FT_BOOLEAN, 4, NULL, 0x2,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_sm_23_wwc,
			{ "WWC", "json.3gpp.suppfeat.wwc",
			FT_BOOLEAN, 4, NULL, 0x4,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_sm_24_qosmonitoring,
			{ "QosMonitoring", "json.3gpp.suppfeat.qosmonitoring",
			FT_BOOLEAN, 4, NULL, 0x8,
			NULL, HFILL }
		},

		{ &hf_json_3gpp_suppfeat_npcf_sm_25_authorizationwithrequiredqos,
			{ "AuthorizationWithRequiredQoS", "json.3gpp.suppfeat.authorizationwithrequiredqos",
			FT_BOOLEAN, 4, NULL, 0x1,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_sm_26_enhancedbackgrounddatatransfer,
			{ "EnhancedBackgroundDataTransfer", "json.3gpp.suppfeat.enhancedbackgrounddatatransfer",
			FT_BOOLEAN, 4, NULL, 0x2,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_sm_27_dn_authorization,
			{ "DN-Authorization", "json.3gpp.suppfeat.dn_authorization",
			FT_BOOLEAN, 4, NULL, 0x4,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_sm_28_pdusessionrelcause,
			{ "PDUSessionRelCause", "json.3gpp.suppfeat.pdusessionrelcause",
			FT_BOOLEAN, 4, NULL, 0x8,
			NULL, HFILL }
		},

		{ &hf_json_3gpp_suppfeat_npcf_sm_29_samepcf,
			{ "SamePcf", "json.3gpp.suppfeat.samepcf",
			FT_BOOLEAN, 4, NULL, 0x1,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_sm_30_adcmultiredirection,
			{ "ADCmultiRedirection", "json.3gpp.suppfeat.adcmultiredirection",
			FT_BOOLEAN, 4, NULL, 0x2,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_sm_31_respbasedsessionrel,
			{ "RespBasedSessionRel", "json.3gpp.suppfeat.respbasedsessionrel",
			FT_BOOLEAN, 4, NULL, 0x4,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_sm_32_timesensitivenetworking,
			{ "TimeSensitiveNetworking", "json.3gpp.suppfeat.timesensitivenetworking",
			FT_BOOLEAN, 4, NULL, 0x8,
			NULL, HFILL }
		},

		{ &hf_json_3gpp_suppfeat_npcf_sm_33_emdbv,
			{ "EMDBV", "json.3gpp.suppfeat.emdbv",
			FT_BOOLEAN, 4, NULL, 0x1,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_sm_34_dnnselectionmode,
			{ "DNNSelectionMode", "json.3gpp.suppfeat.dnnselectionmode",
			FT_BOOLEAN, 4, NULL, 0x2,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_sm_35_epsfallbackreport,
			{ "EPSFallbackReport", "json.3gpp.suppfeat.epsfallbackreport",
			FT_BOOLEAN, 4, NULL, 0x4,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_sm_36_policydecisionerrorhandling,
			{ "PolicyDecisionErrorHandling", "json.3gpp.suppfeat.policydecisionerrorhandling",
			FT_BOOLEAN, 4, NULL, 0x8,
			NULL, HFILL }
		},

		{ &hf_json_3gpp_suppfeat_npcf_sm_37_ddneventpolicycontrol,
			{ "DDNEventPolicyControl", "json.3gpp.suppfeat.ddneventpolicycontrol",
			FT_BOOLEAN, 4, NULL, 0x1,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_sm_38_reallocationofcredit,
			{ "ReallocationOfCredit", "json.3gpp.suppfeat.reallocationofcredit",
			FT_BOOLEAN, 4, NULL, 0x2,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_sm_39_bdtpolicyrenegotiation,
			{ "BDTPolicyRenegotiation", "json.3gpp.suppfeat.bdtpolicyrenegotiation",
			FT_BOOLEAN, 4, NULL, 0x4,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_sm_40_extpolicydecisionerrorhandling,
			{ "ExtPolicyDecisionErrorHandling", "json.3gpp.suppfeat.extpolicydecisionerrorhandling",
			FT_BOOLEAN, 4, NULL, 0x8,
			NULL, HFILL }
		},

		{ &hf_json_3gpp_suppfeat_npcf_sm_41_immediatetermination,
			{ "ImmediateTermination", "json.3gpp.suppfeat.immediatetermination",
			FT_BOOLEAN, 4, NULL, 0x1,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_sm_42_aggregateduelocchanges,
			{ "AggregatedUELocChanges", "json.3gpp.suppfeat.aggregateduelocchanges",
			FT_BOOLEAN, 4, NULL, 0x2,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_sm_43_es3xx,
			{ "ES3XX", "json.3gpp.suppfeat.es3xx",
			FT_BOOLEAN, 4, NULL, 0x4,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_sm_44_groupidlistchange,
			{ "GroupIdListChange", "json.3gpp.suppfeat.groupidlistchange",
			FT_BOOLEAN, 4, NULL, 0x8,
			NULL, HFILL }
		},

		{ &hf_json_3gpp_suppfeat_npcf_sm_45_disableuenotification,
			{ "DisableUENotification", "json.3gpp.suppfeat.disableuenotification",
			FT_BOOLEAN, 4, NULL, 0x1,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_sm_46_offlinechonly,
			{ "OfflineChOnly", "json.3gpp.suppfeat.offlinechonly",
			FT_BOOLEAN, 4, NULL, 0x2,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_sm_47_dual_connectivity_redundant_up_paths,
			{ "Dual-Connectivity-redundant-UP-paths", "json.3gpp.suppfeat.dual_connectivity_redundant_up_paths",
			FT_BOOLEAN, 4, NULL, 0x4,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_sm_48_ddneventpolicycontrol2,
			{ "DDNEventPolicyControl2", "json.3gpp.suppfeat.ddneventpolicycontrol2",
			FT_BOOLEAN, 4, NULL, 0x8,
			NULL, HFILL }
		},

		{ &hf_json_3gpp_suppfeat_npcf_sm_49_vplmn_qos_control,
			{ "VPLMN-QoS-Control", "json.3gpp.suppfeat.vplmn_qos_control",
			FT_BOOLEAN, 4, NULL, 0x1,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_sm_50_2g3giwk,
			{ "2G3GIWK", "json.3gpp.suppfeat.2g3giwk",
			FT_BOOLEAN, 4, NULL, 0x2,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_sm_51_timesensitivecommunication,
			{ "TimeSensitiveCommunication", "json.3gpp.suppfeat.timesensitivecommunication",
			FT_BOOLEAN, 4, NULL, 0x4,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_sm_52_enedge,
			{ "EnEDGE", "json.3gpp.suppfeat.enedge",
			FT_BOOLEAN, 4, NULL, 0x8,
			NULL, HFILL }
		},

		{ &hf_json_3gpp_suppfeat_npcf_sm_53_satbackhaulcategorychg,
			{ "SatBackhaulCategoryChg", "json.3gpp.suppfeat.satbackhaulcategorychg",
			FT_BOOLEAN, 4, NULL, 0x1,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_sm_54_chfsetsupport,
			{ "CHFsetSupport", "json.3gpp.suppfeat.chfsetsupport",
			FT_BOOLEAN, 4, NULL, 0x2,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_sm_55_enatsss,
			{ "EnATSSS", "json.3gpp.suppfeat.enatsss",
			FT_BOOLEAN, 4, NULL, 0x4,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_sm_56_mpsfordts,
			{ "MPSforDTS", "json.3gpp.suppfeat.mpsfordts",
			FT_BOOLEAN, 4, NULL, 0x8,
			NULL, HFILL }
		},

		{ &hf_json_3gpp_suppfeat_npcf_sm_57_routinginforemoval,
			{ "RoutingInfoRemoval", "json.3gpp.suppfeat.routinginforemoval",
			FT_BOOLEAN, 4, NULL, 0x1,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_sm_58_epra,
			{ "ePRA", "json.3gpp.suppfeat.epra",
			FT_BOOLEAN, 4, NULL, 0x2,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_sm_59_aminfluence,
			{ "AMInfluence", "json.3gpp.suppfeat.aminfluence",
			FT_BOOLEAN, 4, NULL, 0x4,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_sm_60_pvssupport,
			{ "PvsSupport", "json.3gpp.suppfeat.pvssupport",
			FT_BOOLEAN, 4, NULL, 0x8,
			NULL, HFILL }
		},

		{ &hf_json_3gpp_suppfeat_npcf_sm_61_enena,
			{ "EneNA", "json.3gpp.suppfeat.enena",
			FT_BOOLEAN, 4, NULL, 0x1,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_sm_62_biumr,
			{ "BIUMR", "json.3gpp.suppfeat.biumr",
			FT_BOOLEAN, 4, NULL, 0x2,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_sm_63_easipreplacement,
			{ "EASIPreplacement", "json.3gpp.suppfeat.easipreplacement",
			FT_BOOLEAN, 4, NULL, 0x4,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_sm_64_exposuretoeas,
			{ "ExposureToEAS", "json.3gpp.suppfeat.exposuretoeas",
			FT_BOOLEAN, 4, NULL, 0x8,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_sm_65_simultconnectivity,
			{ "SimultConnectivity", "json.3gpp.suppfeat.simultconnectivity",
			FT_BOOLEAN, 4, NULL, 0x1,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_sm_66_sgwrest,
			{ "SGWRest", "json.3gpp.suppfeat.sgwrest",
			FT_BOOLEAN, 4, NULL, 0x2,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_sm_67_releasetoreactivate,
			{ "ReleaseToReactivate", "json.3gpp.suppfeat.releasetoreactivate",
			FT_BOOLEAN, 4, NULL, 0x4,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_sm_68_easdiscovery,
			{ "EASDiscovery", "json.3gpp.suppfeat.easdiscovery",
			FT_BOOLEAN, 4, NULL, 0x8,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_sm_69_accnetchargid_string,
			{ "AccNetChargId_String", "json.3gpp.suppfeat.accnetchargid_string",
			FT_BOOLEAN, 4, NULL, 0x1,
			NULL, HFILL }
		},

		{ &hf_json_3gpp_suppfeat_npcf_ue_1_pendingtransaction,
			{ "PendingTransaction", "json.3gpp.suppfeat.pendingtransaction",
			FT_BOOLEAN, 4, NULL, 0x1,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_ue_2_plmnchange,
			{ "PlmnChange", "json.3gpp.suppfeat.plmnchange",
			FT_BOOLEAN, 4, NULL, 0x2,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_ue_3_connectivitystatechange,
			{ "ConnectivityStateChange", "json.3gpp.suppfeat.connectivitystatechange",
			FT_BOOLEAN, 4, NULL, 0x4,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_ue_4_v2x,
			{ "V2X", "json.3gpp.suppfeat.v2x",
			FT_BOOLEAN, 4, NULL, 0x8,
			NULL, HFILL }
		},

		{ &hf_json_3gpp_suppfeat_npcf_ue_5_groupidlistchange,
			{ "GroupIdListChange", "json.3gpp.suppfeat.groupidlistchange",
			FT_BOOLEAN, 4, NULL, 0x1,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_ue_6_immediatereport,
			{ "ImmediateReport", "json.3gpp.suppfeat.immediatereport",
			FT_BOOLEAN, 4, NULL, 0x2,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_ue_7_errorresponse,
			{ "ErrorResponse", "json.3gpp.suppfeat.errorresponse",
			FT_BOOLEAN, 4, NULL, 0x4,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_npcf_ue_8_es3xx,
			{ "ES3XX", "json.3gpp.suppfeat.es3xx",
			FT_BOOLEAN, 4, NULL, 0x8,
			NULL, HFILL }
		},

		{ &hf_json_3gpp_suppfeat_npcf_ue_9_prose,
			{ "ProSe", "json.3gpp.suppfeat.prose",
			FT_BOOLEAN, 4, NULL, 0x1,
			NULL, HFILL }
		},

		{ &hf_json_3gpp_suppfeat_nsmf_pdusession_1_ciot,
			{ "CIOT", "json.3gpp.suppfeat.ciot",
			FT_BOOLEAN, 4, NULL, 0x1,
			"Cellular IoT", HFILL }
		},
		{ &hf_json_3gpp_suppfeat_nsmf_pdusession_2_mapdu,
			{ "MAPDU", "json.3gpp.suppfeat.mapdu",
			FT_BOOLEAN, 4, NULL, 0x2,
			"Multi-Access PDU Session", HFILL }
		},
		{ &hf_json_3gpp_suppfeat_nsmf_pdusession_3_dtssa,
			{ "DTSSA", "json.3gpp.suppfeat.dtssa",
			FT_BOOLEAN, 4, NULL, 0x4,
			"Deployments Topologies with specific SMF Service Areas", HFILL }
		},
		{ &hf_json_3gpp_suppfeat_nsmf_pdusession_4_carpt,
			{ "CARPT", "json.3gpp.suppfeat.carpt",
			FT_BOOLEAN, 4, NULL, 0x8,
			"SMF derived CN Assisted RAN parameters Tuning", HFILL }
		},

		{ &hf_json_3gpp_suppfeat_nsmf_pdusession_5_ctxtr,
			{ "CTXTR", "json.3gpp.suppfeat.ctxtr",
			FT_BOOLEAN, 4, NULL, 0x1,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_nsmf_pdusession_6_vqos,
			{ "VQOS", "json.3gpp.suppfeat.vqos",
			FT_BOOLEAN, 4, NULL, 0x2,
			"VPLMN QoS", HFILL }
		},
		{ &hf_json_3gpp_suppfeat_nsmf_pdusession_7_hofail,
			{ "HOFAIL", "json.3gpp.suppfeat.hofail",
			FT_BOOLEAN, 4, NULL, 0x4,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_nsmf_pdusession_8_es3xx,
			{ "ES3XX", "json.3gpp.suppfeat.es3xx",
			FT_BOOLEAN, 4, NULL, 0x8,
			NULL, HFILL }
		},

		{ &hf_json_3gpp_suppfeat_nsmf_pdusession_9_dce2er,
			{ "DCE2ER", "json.3gpp.suppfeat.dce2er",
			FT_BOOLEAN, 4, NULL, 0x1,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_nsmf_pdusession_10_aasn,
			{ "AASN", "json.3gpp.suppfeat.aasn",
			FT_BOOLEAN, 4, NULL, 0x2,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_nsmf_pdusession_11_enedge,
			{ "ENEDGE", "json.3gpp.suppfeat.enedge",
			FT_BOOLEAN, 4, NULL, 0x4,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_nsmf_pdusession_12_scpbu,
			{ "SCPBU", "json.3gpp.suppfeat.scpbu",
			FT_BOOLEAN, 4, NULL, 0x8,
			NULL, HFILL }
		},

		{ &hf_json_3gpp_suppfeat_nsmf_pdusession_13_enpn,
			{ "ENPN", "json.3gpp.suppfeat.enpn",
			FT_BOOLEAN, 4, NULL, 0x1,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_nsmf_pdusession_14_spae,
			{ "SPAE", "json.3gpp.suppfeat.spae",
			FT_BOOLEAN, 4, NULL, 0x2,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_nsmf_pdusession_15_5gsat,
			{ "5GSAT", "json.3gpp.suppfeat.5gsat",
			FT_BOOLEAN, 4, NULL, 0x4,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_nsmf_pdusession_16_upipe,
			{ "UPIPE", "json.3gpp.suppfeat.upipe",
			FT_BOOLEAN, 4, NULL, 0x8,
			"User Plane Integrity Protection with EPS", HFILL }
		},

		{ &hf_json_3gpp_suppfeat_nsmf_pdusession_17_biumr,
			{ "BIUMR", "json.3gpp.suppfeat.biumr",
			FT_BOOLEAN, 4, NULL, 0x1,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_nsmf_pdusession_18_acscr,
			{ "ACSCR", "json.3gpp.suppfeat.acscr",
			FT_BOOLEAN, 4, NULL, 0x2,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_nsmf_pdusession_19_psetr,
			{ "PSETR", "json.3gpp.suppfeat.psetr",
			FT_BOOLEAN, 4, NULL, 0x4,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_nsmf_pdusession_20_dlset,
			{ "DLSET", "json.3gpp.suppfeat.dlset",
			FT_BOOLEAN, 4, NULL, 0x8,
			NULL, HFILL }
		},

		{ &hf_json_3gpp_suppfeat_nsmf_pdusession_21_n9fsc,
			{ "N9FSC", "json.3gpp.suppfeat.n9fsc",
			FT_BOOLEAN, 4, NULL, 0x1,
			NULL, HFILL }
		},

		{ &hf_json_3gpp_suppfeat_nudm_sdm_1_shareddata,
			{ "SharedData", "json.3gpp.suppfeat.shareddata",
			FT_BOOLEAN, 4, NULL, 0x1,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_nudm_sdm_2_immediatereport,
			{ "ImmediateReport", "json.3gpp.suppfeat.immediatereport",
			FT_BOOLEAN, 4, NULL, 0x2,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_nudm_sdm_3_patchreport,
			{ "PatchReport", "json.3gpp.suppfeat.patchreport",
			FT_BOOLEAN, 4, NULL, 0x4,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_nudm_sdm_4_nssaa,
			{ "Nssaa", "json.3gpp.suppfeat.nssaa",
			FT_BOOLEAN, 4, NULL, 0x8,
			NULL, HFILL }
		},

		{ &hf_json_3gpp_suppfeat_nudm_sdm_5_cagfeature,
			{ "CAGFeature", "json.3gpp.suppfeat.cagfeature",
			FT_BOOLEAN, 4, NULL, 0x1,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_nudm_sdm_6_shareddatatreatment,
			{ "SharedDataTreatment", "json.3gpp.suppfeat.shareddatatreatment",
			FT_BOOLEAN, 4, NULL, 0x2,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_nudm_sdm_7_sortransparentsupport,
			{ "sorTransparentSupport", "json.3gpp.suppfeat.sortransparentsupport",
			FT_BOOLEAN, 4, NULL, 0x4,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_nudm_sdm_8_nsac,
			{ "Nsac", "json.3gpp.suppfeat.nsac",
			FT_BOOLEAN, 4, NULL, 0x8,
			NULL, HFILL }
		},

		{ &hf_json_3gpp_suppfeat_nudm_sdm_9_sharedsmsubsdata,
			{ "SharedSmSubsData", "json.3gpp.suppfeat.sharedsmsubsdata",
			FT_BOOLEAN, 4, NULL, 0x1,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_nudm_sdm_10_ena,
			{ "ENA", "json.3gpp.suppfeat.ena",
			FT_BOOLEAN, 4, NULL, 0x2,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_nudm_sdm_11_nssrg,
			{ "Nssrg", "json.3gpp.suppfeat.nssrg",
			FT_BOOLEAN, 4, NULL, 0x4,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_nudm_sdm_12_uputransparentsupport,
			{ "upuTransparentSupport", "json.3gpp.suppfeat.uputransparentsupport",
			FT_BOOLEAN, 4, NULL, 0x8,
			NULL, HFILL }
		},

		{ &hf_json_3gpp_suppfeat_nudm_sdm_13_limitedsubscriptions,
			{ "LimitedSubscriptions", "json.3gpp.suppfeat.limitedsubscriptions",
			FT_BOOLEAN, 4, NULL, 0x1,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_nudm_sdm_14_snpn_id,
			{ "SNPN-ID", "json.3gpp.suppfeat.snpn_id",
			FT_BOOLEAN, 4, NULL, 0x2,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_nudm_sdm_15_ueconsmfdatasubfilter,
			{ "UeConSmfDataSubFilter", "json.3gpp.suppfeat.ueconsmfdatasubfilter",
			FT_BOOLEAN, 4, NULL, 0x4,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_nudm_sdm_16_tempslicesupport,
			{ "TempSliceSupport", "json.3gpp.suppfeat.tempslicesupport",
			FT_BOOLEAN, 4, NULL, 0x8,
			NULL, HFILL }
		},

		{ &hf_json_3gpp_suppfeat_nudm_sdm_17_expectedbehaviourmap,
			{ "ExpectedBehaviourMap", "json.3gpp.suppfeat.expectedbehaviourmap",
			FT_BOOLEAN, 4, NULL, 0x1,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_nudm_sdm_18_shareddataext,
			{ "SharedDataExt", "json.3gpp.suppfeat.shareddataext",
			FT_BOOLEAN, 4, NULL, 0x2,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_nudm_sdm_19_snpnidext,
			{ "SNPN-ID-EXT", "json.3gpp.suppfeat.snpnidext",
			FT_BOOLEAN, 4, NULL, 0x4,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_nudm_sdm_20_caginfowithvalidityperiods,
			{ "CAG-Info-With-Validity-Periods", "json.3gpp.suppfeat.caginfowithvalidityperiods",
			FT_BOOLEAN, 4, NULL, 0x8,
			NULL, HFILL }
		},

		{ &hf_json_3gpp_suppfeat_nudm_uecm_1_shareddata,
			{ "SharedData", "json.3gpp.suppfeat.shareddata",
			FT_BOOLEAN, 4, NULL, 0x1,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_nudm_uecm_2_patchreport,
			{ "PatchReport", "json.3gpp.suppfeat.patchreport",
			FT_BOOLEAN, 4, NULL, 0x2,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_nudm_uecm_3_shareddatatreatment,
			{ "SharedDataTreatment", "json.3gpp.suppfeat.shareddatatreatment",
			FT_BOOLEAN, 4, NULL, 0x4,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_nudm_uecm_4_cagfeature,
			{ "CAGFeature", "json.3gpp.suppfeat.cagfeature",
			FT_BOOLEAN, 4, NULL, 0x8,
			NULL, HFILL }
		},

		{ &hf_json_3gpp_suppfeat_nudm_uecm_5_deregistrationresponsebody,
			{ "DeRegistrationResponseBody", "json.3gpp.suppfeat.deregistrationresponsebody",
			FT_BOOLEAN, 4, NULL, 0x1,
			NULL, HFILL }
		},

		{ &hf_json_3gpp_suppfeat_nudm_ee_1_patchreport,
			{ "PatchReport", "json.3gpp.suppfeat.patchreport",
			FT_BOOLEAN, 4, NULL, 0x1,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_nudm_ee_2_enena,
			{ "EneNA", "json.3gpp.suppfeat.enena",
			FT_BOOLEAN, 4, NULL, 0x2,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_nudm_ee_3_dgem,
			{ "DGEM", "json.3gpp.suppfeat.dgem",
			FT_BOOLEAN, 4, NULL, 0x4,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_nudm_ee_4_iersr,
			{ "IERSR", "json.3gpp.suppfeat.iersr",
			FT_BOOLEAN, 4, NULL, 0x8,
			NULL, HFILL }
		},

		{ &hf_json_3gpp_suppfeat_nudm_ee_5_enaph3,
			{ "ENAPH3", "json.3gpp.suppfeat.enaph3",
			FT_BOOLEAN, 4, NULL, 0x1,
			NULL, HFILL }
		},

		{ &hf_json_3gpp_suppfeat_nudm_pp_1_patchreport,
			{ "PatchReport", "json.3gpp.suppfeat.patchreport",
			FT_BOOLEAN, 4, NULL, 0x1,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_nudm_pp_2_expectedbehaviourmap,
			{ "ExpectedBehaviourMap", "json.3gpp.suppfeat.expectedbehaviourmap",
			FT_BOOLEAN, 4, NULL, 0x2,
			NULL, HFILL }
		},
		{ &hf_json_3gpp_suppfeat_nudm_pp_3_membersdata,
			{ "MembersData", "json.3gpp.suppfeat.membersdata",
			FT_BOOLEAN, 4, NULL, 0x4,
			NULL, HFILL }
		},
	};

	static int *ett[] = {
		&ett_json_base64decoded_eps_ie,
		&ett_json_base64decoded_nas5g_ie,
		&ett_json_3gpp_data,
	};

	static ei_register_info ei[] = {
		{ &ei_json_3gpp_data_not_decoded,{ "json.3gpp.data_not_decoded", PI_UNDECODED, PI_NOTE, "Data not decoded by WS yet", EXPFILL } },
		{ &ei_json_3gpp_encoding_error,{ "json.3gpp.encoding_error", PI_UNDECODED, PI_ERROR, "Data wrongly encoded", EXPFILL } },
	};

	expert_module_t* expert_json_3gpp;

	/* Required function calls to register the header fields and subtrees used */
	proto_json_3gpp = proto_register_protocol("JSON 3GPP","JSON_3GPP", "json.3gpp");
	proto_register_field_array(proto_json_3gpp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_json_3gpp = expert_register_protocol(proto_json_3gpp);
	expert_register_field_array(expert_json_3gpp, ei, array_length(ei));

	/* Fill hash table with static headers */
	register_static_headers();
}

void
proto_reg_handoff_json_3gpp(void)
{
	proto_http = proto_get_id_by_filter_name("http");
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
