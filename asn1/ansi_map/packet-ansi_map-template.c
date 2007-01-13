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

#include "packet-ansi_map-hf.c"

/* Initialize the subtree pointers */
static gint ett_ansi_map = -1;
static gint ett_mintype = -1;
static gint ett_digitstype = -1;
static gint ett_billingid = -1;
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

#include "packet-ansi_map-ett.c"

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
			break;
		case 2:
			/* IA5 Coding */
			proto_tree_add_item(subtree, hf_ansi_map_ia5_digits, tvb, offset, -1, FALSE);
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
			break;
		case 2:
			/* IA5 Coding */
			proto_tree_add_item(subtree, hf_ansi_map_ia5_digits, tvb, offset, -1, FALSE);
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

	item = get_ber_last_created_item();
	subtree = proto_item_add_subtree(item, ett_billingid);
	/* Trunk Group Number (G) Octet 1 */
	proto_tree_add_item(subtree, hf_ansi_map_tgn, tvb, offset, 1, FALSE);
	offset++;
	/* Trunk Member Number (M) Octet2 */
	proto_tree_add_item(subtree, hf_ansi_map_tmn, tvb, offset, 1, FALSE);
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


#include "packet-ansi_map-fn.c"

static int dissect_invokeData(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {


  switch(OperationCode){
   case 1: /*Handoff Measurement Request*/
	   offset = dissect_ansi_map_HandoffMeasurementRequest(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case 2: /*Facilities Directive*/
	   offset = dissect_ansi_map_FacilitiesDirective(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case 3: /*Mobile On Channel*/
	   proto_tree_add_text(tree, tvb, offset, -1, "Unknown invokeData blob");
	   break;
   case 4: /*Handoff Back*/
	   offset = dissect_ansi_map_HandoffBack(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case 5: /*Facilities Release*/
	   offset = dissect_ansi_map_FacilitiesRelease(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case 6: /*Qualification Request*/
	   offset = dissect_ansi_map_QualificationRequest(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case 7: /*Qualification Directive*/
	   offset = dissect_ansi_map_QualificationDirective(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case 8: /*Blocking*/
	   offset = dissect_ansi_map_Blocking(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case 9: /*Unblocking*/
	   offset = dissect_ansi_map_Unblocking(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case 10: /*Reset Circuit*/
	   offset = dissect_ansi_map_ResetCircuit(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case 11: /*Trunk Test*/
	   offset = dissect_ansi_map_TrunkTest(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case 12: /*Trunk Test Disconnect*/
	  offset = dissect_ansi_map_TrunkTestDisconnect(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
   case  13: /*Registration Notification*/
	  offset = dissect_ansi_map_RegistrationNotification(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
   case  14: /*Registration Cancellation*/
	   offset = dissect_ansi_map_RegistrationCancellation(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
   case  15: /*Location Request*/
	   offset = dissect_ansi_map_LocationRequest(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  16: /*Routing Request*/
	   offset = dissect_ansi_map_RoutingRequest(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  17: /*Feature Request*/
	   offset = dissect_ansi_map_FeatureRequest(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  18: /*Reserved 18 (Service Profile Request, IS-41-C)*/
	   proto_tree_add_text(tree, tvb, offset, -1, "Unknown invokeData blob(18 (Service Profile Request, IS-41-C)");
	   break;
   case  19: /*Reserved 19 (Service Profile Directive, IS-41-C)*/
	   proto_tree_add_text(tree, tvb, offset, -1, "Unknown invokeData blob(19 Service Profile Directive, IS-41-C)");
	   break;
   case  20: /*Unreliable Roamer Data Directive*/
	   offset = dissect_ansi_map_UnreliableRoamerDataDirective(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  21: /*Reserved 21 (Call Data Request, IS-41-C)*/
	   proto_tree_add_text(tree, tvb, offset, -1, "Unknown invokeData blob(Reserved 21 (Call Data Request, IS-41-C)");
	   break;
   case  22: /*MS Inactive*/
	   offset = dissect_ansi_map_MSInactive(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  23: /*Transfer To Number Request*/
	   offset = dissect_ansi_map_TransferToNumberRequest(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  24: /*Redirection Request*/
	   offset = dissect_ansi_map_RedirectionRequest(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  25: /*Handoff To Third*/
	   offset = dissect_ansi_map_HandoffToThird(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  26: /*Flash Request*/
	   offset = dissect_ansi_map_FlashRequest(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  27: /*Authentication Directive*/
	   offset = dissect_ansi_map_AuthenticationDirective(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  28: /*Authentication Request*/
	   offset = dissect_ansi_map_AuthenticationRequest(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  29: /*Base Station Challenge*/
	   offset = dissect_ansi_map_BaseStationChallenge(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  30: /*Authentication Failure Report*/
	   offset = dissect_ansi_map_AuthenticationFailureReport(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  31: /*Count Request*/
	   offset = dissect_ansi_map_CountRequest(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  32: /*Inter System Page*/
	   offset = dissect_ansi_map_InterSystemPage(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  33: /*Unsolicited Response*/
	   offset = dissect_ansi_map_UnsolicitedResponse(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  34: /*Bulk Deregistration*/
	   offset = dissect_ansi_map_BulkDeregistration(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  35: /*Handoff Measurement Request 2*/
	   offset = dissect_ansi_map_HandoffMeasurementRequest2(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  36: /*Facilities Directive 2*/
	   offset = dissect_ansi_map_FacilitiesDirective2(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  37: /*Handoff Back 2*/
	   offset = dissect_ansi_map_HandoffBack2(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  38: /*Handoff To Third 2*/
	   offset = dissect_ansi_map_HandoffToThird2(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  39: /*Authentication Directive Forward*/
	   offset = dissect_ansi_map_AuthenticationDirectiveForward(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  40: /*Authentication Status Report*/
	   offset = dissect_ansi_map_AuthenticationStatusReport(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  41: /*Reserved 41*/
	   proto_tree_add_text(tree, tvb, offset, -1, "Reserved 41, Unknown invokeData blob");
	   break;
   case  42: /*Information Directive*/
	   offset = dissect_ansi_map_InformationDirective(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  43: /*Information Forward*/
	   offset = dissect_ansi_map_InformationForward(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  44: /*Inter System Answer*/
	   offset = dissect_ansi_map_InterSystemAnswer(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  45: /*Inter System Page 2*/
	   offset = dissect_ansi_map_InterSystemPage2(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  46: /*Inter System Setup*/
	   offset = dissect_ansi_map_InterSystemSetup(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
  case  47: /*OriginationRequest*/
	  offset = dissect_ansi_map_OriginationRequest(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_OriginationRequest_PDU);
	  break;
  case  48: /*Random Variable Request*/
	  offset = dissect_ansi_map_RandomVariableRequest(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  49: /*Redirection Directive*/
	  offset = dissect_ansi_map_RedirectionDirective(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  50: /*Remote User Interaction Directive*/
	  offset = dissect_ansi_map_RemoteUserInteractionDirective(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  51: /*SMS Delivery Backward*/
	  offset = dissect_ansi_map_SMSDeliveryBackward(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  52: /*SMS Delivery Forward*/
	  offset = dissect_ansi_map_SMSDeliveryForward(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  53: /*SMS Delivery Point to Point*/
	  offset = dissect_ansi_map_SMSDeliveryPointToPoint(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  54: /*SMS Notification*/
	  offset = dissect_ansi_map_SMSNotification(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  55: /*SMS Request*/
	  offset = dissect_ansi_map_SMSRequest(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
	  /* End N.S0005*/
	  /* N.S0010-0 v 1.0 */
	  /* N.S0011-0 v 1.0 */
  case  56: /*OTASP Request 6.4.2.CC*/
	  offset = dissect_ansi_map_OTASPRequest(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
	  /*End N.S0011-0 v 1.0 */
  case  57: /*Information Backward*/
	  offset = offset;
	  break;
	  /*  N.S0008-0 v 1.0 */
  case  58: /*Change Facilities*/
	  offset = dissect_ansi_map_ChangeFacilities(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  59: /*Change Service*/
	  offset = dissect_ansi_map_ChangeService(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
	  /* End N.S0008-0 v 1.0 */	
  case  60: /*Parameter Request*/
	  offset = dissect_ansi_map_ParameterRequest(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  61: /*TMSI Directive*/
	  offset = dissect_ansi_map_TMSIDirective(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
	  /*End  N.S0010-0 v 1.0 */
  case  62: /*Reserved 62*/
	  proto_tree_add_text(tree, tvb, offset, -1, "Unknown invokeData blob(Reserved 62)");
	  break;
  case  63: /*Service Request N.S0012-0 v 1.0*/
	  offset = dissect_ansi_map_ServiceRequest(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
	  /* N.S0013 */
  case  64: /*Analyzed Information Request*/
	  offset = dissect_ansi_map_AnalyzedInformation(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  65: /*Connection Failure Report*/
	  offset = dissect_ansi_map_ConnectionFailureReport(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  66: /*Connect Resource*/
	  offset = dissect_ansi_map_ConnectResource(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  67: /*Disconnect Resource*/
	  /* No data */
	  break;
  case  68: /*Facility Selected and Available*/
	  offset = dissect_ansi_map_FacilitySelectedAndAvailable(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  69: /*Instruction Request*/
	  /* No data */
	  break;
  case  70: /*Modify*/
	  offset = dissect_ansi_map_Modify(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  71: /*Reset Timer*/
	  /*No Data*/
	  break;
  case  72: /*Search*/
	  offset = dissect_ansi_map_Search(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  73: /*Seize Resource*/
	  offset = dissect_ansi_map_SeizeResource(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  74: /*SRF Directive*/
	  offset = dissect_ansi_map_SRFDirective(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  75: /*T Busy*/
	  offset = dissect_ansi_map_TBusy(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  76: /*T NoAnswer*/
	  offset = dissect_ansi_map_TNoAnswer(TRUE, tvb, offset, pinfo, tree, -1);
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
	  offset = dissect_ansi_map_MessageDirective(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
	  /*END N.S0024*/
	  /* N.S0018 PN-4287*/
  case  80: /*Bulk Disconnection*/
	  offset = dissect_ansi_map_BulkDisconnection(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  81: /*Call Control Directive*/
	  offset = dissect_ansi_map_CallControlDirective(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  82: /*O Answer*/
	  offset = dissect_ansi_map_OAnswer(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  83: /*O Disconnect*/
	  offset = dissect_ansi_map_ODisconnect(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  84: /*Call Recovery Report*/
	  offset = dissect_ansi_map_CallRecoveryReport(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  85: /*T Answer*/
	  offset = dissect_ansi_map_TAnswer(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  86: /*T Disconnect*/
	  offset = dissect_ansi_map_TDisconnect(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  87: /*Unreliable Call Data*/
	  offset = dissect_ansi_map_UnreliableCallData(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
	  /* N.S0018 PN-4287*/
	  /*N.S0004 */
  case  88: /*O CalledPartyBusy*/
	  offset = dissect_ansi_map_OCalledPartyBusy(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  89: /*O NoAnswer*/
	  offset = dissect_ansi_map_ONoAnswer(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  90: /*Position Request*/
	  offset = dissect_ansi_map_PositionRequest(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  91: /*Position Request Forward*/
	  offset = dissect_ansi_map_PositionRequestForward(TRUE, tvb, offset, pinfo, tree, -1);
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
	  offset = dissect_ansi_map_ACGDirective(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
	  /* END 3GPP2 N.S0023-0 */
  case  98: /*Roamer Database Verification Request*/
	  offset = dissect_ansi_map_RoamerDatabaseVerificationRequest(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
	  /* N.S0029 */
  case  99: /*Add Service*/
	  offset = dissect_ansi_map_AddService(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  100: /*Drop Service*/
	  offset = dissect_ansi_map_DropService(TRUE, tvb, offset, pinfo, tree, -1);
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
	   offset = dissect_ansi_map_HandoffMeasurementRequestRes(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case 2: /*Facilities Directive*/
	   offset = dissect_ansi_map_FacilitiesDirectiveRes(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case 4: /*Handoff Back*/
	   offset = dissect_ansi_map_HandoffBackRes(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case 5: /*Facilities Release*/
	   offset = dissect_ansi_map_FacilitiesReleaseRes(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
  case 6: /*Qualification Request*/
	   offset = dissect_ansi_map_QualificationRequestRes(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case 10: /*Reset Circuit*/
	   offset = dissect_ansi_map_ResetCircuitRes(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case 13: /*Registration Notification*/
	  offset = dissect_ansi_map_RegistrationNotificationRes(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
   case  14: /*Registration Cancellation*/
      offset = dissect_ansi_map_RegistrationCancellationRes(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
   case  15: /*Location Request*/
	   offset = dissect_ansi_map_LocationRequestRes(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  16: /*Routing Request*/
	   offset = dissect_ansi_map_RoutingRequestRes(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  17: /*Feature Request*/
	   offset = dissect_ansi_map_FeatureRequestRes(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  23: /*Transfer To Number Request*/
	   offset = dissect_ansi_map_TransferToNumberRequestRes(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  25: /*Handoff To Third*/
	   offset = dissect_ansi_map_HandoffToThirdRes(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  27: /*Authentication Directive*/
	   offset = dissect_ansi_map_AuthenticationDirectiveRes(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  28: /*Authentication Request*/
	   offset = dissect_ansi_map_AuthenticationRequestRes(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  30: /*Authentication Failure Report*/
	   offset = dissect_ansi_map_AuthenticationFailureReportRes(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  31: /*Count Request*/
	   offset = dissect_ansi_map_CountRequestRes(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  32: /*Inter System Page*/
	   offset = dissect_ansi_map_InterSystemPageRes(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  33: /*Unsolicited Response*/
	   offset = dissect_ansi_map_UnsolicitedResponseRes(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  35: /*Handoff Measurement Request 2*/
	   offset = dissect_ansi_map_HandoffMeasurementRequest2Res(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  36: /*Facilities Directive 2*/
	   offset = dissect_ansi_map_FacilitiesDirective2Res(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  37: /*Handoff Back 2*/
	   offset = dissect_ansi_map_HandoffBack2Res(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  38: /*Handoff To Third 2*/
	   offset = dissect_ansi_map_HandoffToThird2Res(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  39: /*Authentication Directive Forward*/
	   offset = dissect_ansi_map_AuthenticationDirectiveForwardRes(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  40: /*Authentication Status Report*/
	   offset = dissect_ansi_map_AuthenticationStatusReportRes(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
			 /*Reserved 41*/
   case  43: /*Information Forward*/
	   offset = dissect_ansi_map_InformationForwardRes(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  45: /*Inter System Page 2*/
	   offset = dissect_ansi_map_InterSystemPage2Res(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  46: /*Inter System Setup*/
	   offset = dissect_ansi_map_InterSystemSetupRes(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
  case  47: /*OriginationRequest*/
	  offset = dissect_ansi_map_OriginationRequestRes(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  48: /*Random Variable Request*/
	  offset = dissect_ansi_map_RandomVariableRequestRes(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  50: /*Remote User Interaction Directive*/
	  offset = dissect_ansi_map_RemoteUserInteractionDirectiveRes(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  51: /*SMS Delivery Backward*/
	  offset = dissect_ansi_map_SMSDeliveryBackwardRes(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  52: /*SMS Delivery Forward*/
	  offset = dissect_ansi_map_SMSDeliveryForwardRes(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  53: /*SMS Delivery Point to Point*/
	  offset = dissect_ansi_map_SMSDeliveryPointToPointRes(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  54: /*SMS Notification*/
	  offset = dissect_ansi_map_SMSNotificationRes(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  55: /*SMS Request*/
	  offset = dissect_ansi_map_SMSRequestRes(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
	  /*  N.S0008-0 v 1.0 */
  case  56: /*OTASP Request 6.4.2.CC*/
	  offset = dissect_ansi_map_OTASPRequestRes(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  58: /*Change Facilities*/
	  offset = dissect_ansi_map_ChangeFacilitiesRes(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  59: /*Change Service*/
	  offset = dissect_ansi_map_ChangeServiceRes(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  60: /*Parameter Request*/
	  offset = dissect_ansi_map_ParameterRequestRes(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  61: /*TMSI Directive*/
	  offset = dissect_ansi_map_TMSIDirectiveRes(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  63: /*Service Request*/
	  offset = dissect_ansi_map_ServiceRequestRes(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
	  /* N.S0013 */
  case  64: /*Analyzed Information Request*/
	  offset = dissect_ansi_map_AnalyzedInformationRes(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  68: /*Facility Selected and Available*/
	  offset = dissect_ansi_map_FacilitySelectedAndAvailableRes(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  70: /*Modify*/
	  offset = dissect_ansi_map_ModifyRes(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  72: /*Search*/
	  offset = dissect_ansi_map_SearchRes(TRUE, tvb, offset, pinfo, tree, -1);;
	  break;
  case  73: /*Seize Resource*/
	  offset = dissect_ansi_map_SeizeResourceRes(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  74: /*SRF Directive*/
	  offset = dissect_ansi_map_SRFDirectiveRes(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  75: /*T Busy*/
	  offset = dissect_ansi_map_TBusyRes(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  76: /*T NoAnswer*/
	  offset = dissect_ansi_map_TNoAnswerRes(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  81: /*Call Control Directive*/
	  offset = dissect_ansi_map_CallControlDirectiveRes(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  83: /*O Disconnect*/
	  offset = dissect_ansi_map_ODisconnectRes(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  86: /*T Disconnect*/
	  offset = dissect_ansi_map_TDisconnectRes(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  88: /*O CalledPartyBusy*/
	  offset = dissect_ansi_map_OCalledPartyBusyRes(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
   case  89: /*O NoAnswer*/
	  offset = dissect_ansi_map_ONoAnswerRes(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  90: /*Position Request*/
	  offset = dissect_ansi_map_PositionRequestRes(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  91: /*Position Request Forward*/
	  offset = dissect_ansi_map_PositionRequestForwardRes(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  98: /*Roamer Database Verification Request*/
	  offset = dissect_ansi_map_RoamerDatabaseVerificationRequestRes(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  99: /*Add Service*/
	  offset = dissect_ansi_map_AddServiceRes(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  100: /*Drop Service*/
	  offset = dissect_ansi_map_DropServiceRes(TRUE, tvb, offset, pinfo, tree, -1);
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
      { "Power Class: (PC)", "ansi_map.cdmastationclassmark.pc",
        FT_UINT8, BASE_DEC, VALS(ansi_map_CDMAStationClassMark_pc_vals), 0x03,
        "Power Class: (PC)", HFILL }},

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
		
#include "packet-ansi_map-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
	  &ett_ansi_map,
	  &ett_mintype,
	  &ett_digitstype,
	  &ett_billingid,
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
#include "packet-ansi_map-ettarr.c"
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





