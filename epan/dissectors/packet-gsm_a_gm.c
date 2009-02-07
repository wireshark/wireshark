/* packet-gsm_a_gm.c
 * Routines for GSM A Interface GPRS Mobilty Management and GPRS Session Management
 *
 * Copyright 2003, Michael Lum <mlum [AT] telostech.com>
 * In association with Telos Technology Inc.
 *
 * Added the GPRS Mobility Managment Protocol and
 * the GPRS Session Managment Protocol
 *   Copyright 2004, Rene Pilz <rene.pilz [AT] ftw.com>
 *   In association with Telecommunications Research Center
 *   Vienna (ftw.)Betriebs-GmbH within the Project Metawin.
 *
 * Title		3GPP			Other
 *
 *   Reference [7]
 *   Mobile radio interface Layer 3 specification;
 *   Core network protocols;
 *   Stage 3
 *   (3GPP TS 24.008 version 5.9.0 Release 5)
 *
 *   Reference [8]
 *   Mobile radio interface Layer 3 specification;
 *   Core network protocols;
 *   Stage 3
 *   (3GPP TS 24.008 version 6.7.0 Release 6)
 *	 (3GPP TS 24.008 version 6.8.0 Release 6)
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>

#include <string.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/tap.h>
#include <epan/asn1.h>

#include "packet-bssap.h"
#include "packet-sccp.h"
#include "packet-ber.h"
#include "packet-q931.h"
#include "packet-gsm_a_common.h"
#include "packet-ipv6.h"
#include "packet-e212.h"
#include "packet-ppp.h"

/* PROTOTYPES/FORWARDS */

const value_string gsm_a_dtap_msg_gmm_strings[] = {
	{ 0x01,	"Attach Request" },
	{ 0x02,	"Attach Accept" },
	{ 0x03,	"Attach Complete" },
	{ 0x04,	"Attach Reject" },
	{ 0x05,	"Detach Request" },
	{ 0x06,	"Detach Accept" },
	{ 0x08,	"Routing Area Update Request" },
	{ 0x09,	"Routing Area Update Accept" },
	{ 0x0a,	"Routing Area Update Complete" },
	{ 0x0b,	"Routing Area Update Reject" },
	{ 0x0c,	"Service Request" },
	{ 0x0d,	"Service Accept" },
	{ 0x0e,	"Service Reject" },
	{ 0x10,	"P-TMSI Reallocation Command" },
	{ 0x11,	"P-TMSI Reallocation Complete" },
	{ 0x12,	"Authentication and Ciphering Req" },
	{ 0x13,	"Authentication and Ciphering Resp" },
	{ 0x14,	"Authentication and Ciphering Rej" },
	{ 0x1c,	"Authentication and Ciphering Failure" },
	{ 0x15,	"Identity Request" },
	{ 0x16,	"Identity Response" },
	{ 0x20,	"GMM Status" },
	{ 0x21,	"GMM Information" },
	{ 0, NULL }
};

const value_string gsm_a_dtap_msg_sm_strings[] = {
	{ 0x41,	"Activate PDP Context Request" },
	{ 0x42,	"Activate PDP Context Accept" },
	{ 0x43,	"Activate PDP Context Reject" },
	{ 0x44,	"Request PDP Context Activation" },
	{ 0x45,	"Request PDP Context Activation rej." },
	{ 0x46,	"Deactivate PDP Context Request" },
	{ 0x47,	"Deactivate PDP Context Accept" },
	{ 0x48,	"Modify PDP Context Request(Network to MS direction)" },
	{ 0x49,	"Modify PDP Context Accept (MS to network direction)" },
	{ 0x4a,	"Modify PDP Context Request(MS to network direction)" },
	{ 0x4b,	"Modify PDP Context Accept (Network to MS direction)" },
	{ 0x4c,	"Modify PDP Context Reject" },
	{ 0x4d,	"Activate Secondary PDP Context Request" },
	{ 0x4e,	"Activate Secondary PDP Context Accept" },
	{ 0x4f,	"Activate Secondary PDP Context Reject" },
	{ 0x50,	"Reserved: was allocated in earlier phases of the protocol" },
	{ 0x51,	"Reserved: was allocated in earlier phases of the protocol" },
	{ 0x52,	"Reserved: was allocated in earlier phases of the protocol" },
	{ 0x53,	"Reserved: was allocated in earlier phases of the protocol" },
	{ 0x54,	"Reserved: was allocated in earlier phases of the protocol" },
	{ 0x55,	"SM Status" },
	{ 0x56,	"Activate MBMS Context Request" },
	{ 0x57,	"Activate MBMS Context Accept" },
	{ 0x58,	"Activate MBMS Context Reject" },
	{ 0x59,	"Request MBMS Context Activation" },
	{ 0x5a,	"Request MBMS Context Activation Reject" },
	{ 0, NULL }
};

const value_string gsm_gm_elem_strings[] = {
	/* GPRS Mobility Management Information Elements 10.5.5 */
	{ 0x00,	"Attach Result" },
	{ 0x00,	"Attach Type" },
	{ 0x00,	"Cipher Algorithm" },
	{ 0x00,	"TMSI Status" },
	{ 0x00,	"Detach Type" },
	{ 0x00,	"DRX Parameter" },
	{ 0x00,	"Force to Standby" },
	{ 0x00, "Force to Standby" },
	{ 0x00,	"P-TMSI Signature" },
	{ 0x00,	"P-TMSI Signature 2" },
	{ 0x00,	"Identity Type 2" },
	{ 0x00,	"IMEISV Request" },
	{ 0x00,	"Receive N-PDU Numbers List" },
	{ 0x00,	"MS Network Capability" },
	{ 0x00,	"MS Radio Access Capability" },
	{ 0x00,	"GMM Cause" },
	{ 0x00,	"Routing Area Identification" },
	{ 0x00,	"Update Result" },
	{ 0x00, "Update Type" },
	{ 0x00,	"A&C Reference Number" },
	{ 0x00, "A&C Reference Number" },
	{ 0x00,	"Service Type" },
	{ 0x00,	"Cell Notification" },
	{ 0x00, "PS LCS Capability" },
	{ 0x00,	"Network Feature Support" },
	{ 0x00, "Inter RAT information container" },
	/* Session Management Information Elements 10.5.6 */
	{ 0x00,	"Access Point Name" },
	{ 0x00,	"Network Service Access Point Identifier" },
	{ 0x00,	"Protocol Configuration Options" },
	{ 0x00,	"Packet Data Protocol Address" },
	{ 0x00,	"Quality Of Service" },
	{ 0x00,	"SM Cause" },
	{ 0x00,	"Linked TI" },
	{ 0x00,	"LLC Service Access Point Identifier" },
	{ 0x00,	"Tear Down Indicator" },
	{ 0x00,	"Packet Flow Identifier" },
	{ 0x00,	"Traffic Flow Template" },
	/* GPRS Common Information Elements 10.5.7 */
	{ 0x00,	"PDP Context Status" },
	{ 0x00,	"Radio Priority" },
	{ 0x00,	"GPRS Timer" },
	{ 0x00,	"GPRS Timer 2" },
	{ 0x00, "Radio Priority 2"},
	{ 0x00,	"MBMS context status"},
	{ 0x00, "Spare Nibble"},
	{ 0, NULL }
};

#define	DTAP_GMM_IEI_MASK	0xff
#define	DTAP_SM_IEI_MASK	0xff

/* Initialize the protocol and registered fields */
static int proto_a_gm = -1;

static int hf_gsm_a_dtap_msg_gmm_type = -1;
static int hf_gsm_a_dtap_msg_sm_type = -1;
int hf_gsm_a_gm_elem_id = -1;
static int hf_gsm_a_qos_delay_cls	= -1;
static int hf_gsm_a_qos_qos_reliability_cls = -1;
static int hf_gsm_a_qos_traffic_cls = -1;
static int hf_gsm_a_qos_del_order = -1;
static int hf_gsm_a_qos_del_of_err_sdu = -1;
static int hf_gsm_a_qos_ber = -1;
static int hf_gsm_a_qos_sdu_err_rat = -1;
static int hf_gsm_a_qos_traff_hdl_pri = -1;

static int hf_gsm_a_gmm_split_on_ccch = -1;
static int hf_gsm_a_gmm_non_drx_timer = -1;
static int hf_gsm_a_gmm_cn_spec_drs_cycle_len_coef = -1;

static int hf_gsm_a_ptmsi_sig =-1;
static int hf_gsm_a_ptmsi_sig2 =-1;

static int hf_gsm_a_tft_op_code = -1;
static int hf_gsm_a_tft_e_bit = -1;
static int hf_gsm_a_tft_pkt_flt = -1;
static int hf_gsm_a_tft_ip4_address = -1;
static int hf_gsm_a_tft_ip4_mask = -1;
static int hf_gsm_a_tft_ip6_address = -1;
static int hf_gsm_a_tft_ip6_mask = -1;
static int hf_gsm_a_tft_protocol_header = -1;
static int hf_gsm_a_tft_port = -1;
static int hf_gsm_a_tft_port_low = -1;
static int hf_gsm_a_tft_port_high = -1;
static int hf_gsm_a_tft_security = -1;
static int hf_gsm_a_tft_traffic_mask = -1;

/* Initialize the subtree pointers */
static gint ett_tc_component = -1;
static gint ett_tc_invoke_id = -1;
static gint ett_tc_linked_id = -1;
static gint ett_tc_opr_code = -1;
static gint ett_tc_err_code = -1;
static gint ett_tc_prob_code = -1;
static gint ett_tc_sequence = -1;

static gint ett_gmm_drx = -1;
static gint ett_gmm_detach_type = -1;
static gint ett_gmm_attach_type = -1;
static gint ett_gmm_context_stat = -1;
static gint ett_gmm_update_type = -1;
static gint ett_gmm_radio_cap = -1;
static gint ett_gmm_rai = -1;

static gint ett_sm_tft = -1;

static dissector_handle_t data_handle;
static dissector_handle_t rrc_irat_ho_info_handle;

static dissector_table_t gprs_sm_pco_subdissector_table; /* GPRS SM PCO PPP Protocols */

#define	NUM_GSM_GM_ELEM (sizeof(gsm_gm_elem_strings)/sizeof(value_string))
gint ett_gsm_gm_elem[NUM_GSM_GM_ELEM];

const	gchar pdp_str[2][20]={ "PDP-INACTIVE", "PDP-ACTIVE" };

/*
 * [7] 10.5.5.1
 */
static guint16
de_gmm_attach_res(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint8	oct;
	guint32	curr_offset;
	const gchar	*str;

	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	switch(oct&7)
	{
		case 1: str="GPRS only attached"; break;
		case 3: str="Combined GPRS/IMSI attached";	break;
		default: str="reserved";
	}

	proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"Attach Result: (%u) %s",
		oct&7,
		str);

	curr_offset++;

	/* no length check possible */

	return(curr_offset - offset);
}

/*
 * [7] 10.5.5.2
 */
static guint16
de_gmm_attach_type(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint8	oct;
	guint8	oct_ciph;
	guint32	curr_offset;
	const gchar	*str_follow;
	const gchar	*str_attach;
	proto_item	*tf = NULL;
	proto_tree	*tf_tree = NULL;

	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);
	oct_ciph = oct>>4;

	oct &= 0x0f;

	switch(oct&7)
	{
		case 1: str_attach="GPRS attach"; break;
		case 2: str_attach="GPRS attach while IMSI attached"; break;
		case 3: str_attach="Combined GPRS/IMSI attach"; break;
		default: str_attach="reserved";
	}
	switch(oct&8)
	{
		case 8: str_follow="Follow-on request pending"; break;
		default: str_follow="No follow-on request pending";
	}

	tf = proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"Attach Type");

	tf_tree = proto_item_add_subtree(tf, ett_gmm_attach_type );

	proto_tree_add_text(tf_tree,
		tvb, curr_offset, 1,
		"Type: (%u) %s",
		oct&7,
		str_attach);
	proto_tree_add_text(tf_tree,
		tvb, curr_offset, 1,
		"Follow: (%u) %s",
		(oct>>3)&1,
		str_follow);

	/* The ciphering key sequence number is added here */
	proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"Ciphering key sequence number: 0x%02x (%u)",
		oct_ciph,
		oct_ciph);

	curr_offset++;

	/* no length check possible */

	return(curr_offset - offset);
}

/*
 * [7] 10.5.5.3
 */
static guint16
de_gmm_ciph_alg(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint8	oct;
	guint32	curr_offset;
	const gchar *str;

	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	switch(oct&7)
	{
		case 0: str="ciphering not used"; break;
		case 1: str="GPRS Encryption Algorithm GEA/1"; break;
		case 2: str="GPRS Encryption Algorithm GEA/2"; break;
		case 3: str="GPRS Encryption Algorithm GEA/3"; break;
		case 4: str="GPRS Encryption Algorithm GEA/4"; break;
		case 5: str="GPRS Encryption Algorithm GEA/5"; break;
		case 6: str="GPRS Encryption Algorithm GEA/6"; break;
		case 7: str="GPRS Encryption Algorithm GEA/7"; break;
		default: str="This should never happen";
	}

	proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"Ciphering Algorithm: (%u) %s",
		oct&7,
		str);

	curr_offset++;

	/* no length check possible */

	return(curr_offset - offset);
}

/*
 * [7] 10.5.5.4
 */
static guint16
de_gmm_tmsi_stat(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint8	oct;
	guint32	curr_offset;
	const gchar *str;

	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	switch(oct&1)
	{
		case 0: str="no valid TMSI available"; break;
		case 1: str="valid TMSI available"; break;
		default: str="This should never happen";
	}

	proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"TMSI Status: (%u) %s",
		oct&1,
		str);

	curr_offset++;

	/* no length check possible */

	return(curr_offset - offset);
}

/*
 * [7] 10.5.5.5
 */
static guint16
de_gmm_detach_type(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint8	oct;
	guint32	curr_offset;
	const gchar	*str;
	const gchar *str_power;
	proto_item  *tf = NULL;
	proto_tree	  *tf_tree = NULL;

	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	switch(oct&7)
	{
		case 1: str="GPRS detach/re-attach required"; break;
		case 2: str="IMSI detach/re-attach not required"; break;
		case 3: str="Combined GPRS/IMSI detach/IMSI detach (after VLR failure)"; break;
		default: str="Combined GPRS/IMSI detach/re-attach not required";
	}

	switch(oct&8)
	{
		case 8: str_power="power switched off"; break;
		default: str_power="normal detach"; break;
	}

	tf = proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"Detach Type");

	tf_tree = proto_item_add_subtree(tf, ett_gmm_detach_type );

	proto_tree_add_text(tf_tree,
		tvb, curr_offset, 1,
		"Type: (%u) %s",
		oct&7,
		str);

	proto_tree_add_text(tf_tree,
		tvb, curr_offset, 1,
		"Power: (%u) %s",
		(oct>>3)&1,
		str_power);

	curr_offset++;

	/* no length check possible */

	return(curr_offset - offset);
}

/*
 * [7] 10.5.5.6
 *
 * SPLIT on CCCH, octet 3 (bit 4)
 * 0 Split pg cycle on CCCH is not supported by the mobile station
 * 1 Split pg cycle on CCCH is supported by the mobile station
 */
static const true_false_string gsm_a_gmm_split_on_ccch_value  = {
	"Split pg cycle on CCCH is supported by the mobile station",
	"Split pg cycle on CCCH is not supported by the mobile station"
};

/* non-DRX timer, octet 3
 * bit
 * 3 2 1
 */
static const value_string gsm_a_gmm_non_drx_timer_strings[] = {
	{ 0x00,	"no non-DRX mode after transfer state" },
	{ 0x01,	"max. 1 sec non-DRX mode after transfer state" },
	{ 0x02,	"max. 2 sec non-DRX mode after transfer state" },
	{ 0x03,	"max. 4 sec non-DRX mode after transfer state" },
	{ 0x04,	"max. 8 sec non-DRX mode after transfer state" },
	{ 0x05,	"max. 16 sec non-DRX mode after transfer state" },
	{ 0x06,	"max. 32 sec non-DRX mode after transfer state" },
	{ 0x07,	"max. 64 sec non-DRX mode after transfer state" },
	{ 0, NULL },
};
/*
 * CN Specific DRX cycle length coefficient, octet 3
 * bit
 * 8 7 6 5 Iu mode specific
 * 0 0 0 0 CN Specific DRX cycle length coefficient not specified by the MS, ie. the
 * system information value 'CN domain specific DRX cycle length' is used.
 * (Ref 3GPP TS 25.331)
 * 0 1 1 0 CN Specific DRX cycle length coefficient 6
 * 0 1 1 1 CN Specific DRX cycle length coefficient 7
 * 1 0 0 0 CN Specific DRX cycle length coefficient 8
 * 1 0 0 1 CN Specific DRX cycle length coefficient 9
 * All other values shall be interpreted as "CN Specific DRX cycle length coefficient not
 * specified by the MS " by this version of the protocol.
 * NOTE: In Iu mode this field (octet 3 bits 8 to 5) is used, but was spare in earlier
 * versions of this protocol.
 */
static const value_string gsm_a_gmm_cn_spec_drs_cycle_len_coef_strings[] = {
	{ 0x00,	"CN Specific DRX cycle length coefficient not specified by the MS" },
	{ 0x01,	"CN Specific DRX cycle length coefficient not specified by the MS" },
	{ 0x02,	"CN Specific DRX cycle length coefficient not specified by the MS" },
	{ 0x03,	"CN Specific DRX cycle length coefficient not specified by the MS" },
	{ 0x04,	"CN Specific DRX cycle length coefficient not specified by the MS" },
	{ 0x05,	"CN Specific DRX cycle length coefficient not specified by the MS" },
	{ 0x06,	"CN Specific DRX cycle length coefficient 6" },
	{ 0x07,	"CN Specific DRX cycle length coefficient 7" },
	{ 0x08,	"CN Specific DRX cycle length coefficient 8" },
	{ 0x09,	"CN Specific DRX cycle length coefficient 9" },
	{ 0x0a,	"CN Specific DRX cycle length coefficient not specified by the MS" },
	{ 0x0b,	"CN Specific DRX cycle length coefficient not specified by the MS" },
	{ 0x0c,	"CN Specific DRX cycle length coefficient not specified by the MS" },
	{ 0x0d,	"CN Specific DRX cycle length coefficient not specified by the MS" },
	{ 0x0e,	"CN Specific DRX cycle length coefficient not specified by the MS" },
	{ 0x0f,	"CN Specific DRX cycle length coefficient not specified by the MS" },
	{ 0, NULL },
};
guint16
de_gmm_drx_param(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint8	oct;
	guint32	curr_offset;
	const gchar	*str;
	gchar	str_val[3];
	proto_item  *tf = NULL;
	proto_tree  *tf_tree = NULL;

	curr_offset = offset;

	tf = proto_tree_add_text(tree,
		tvb, curr_offset, 2,
		"DRX Parameter");

	tf_tree = proto_item_add_subtree(tf, ett_gmm_drx );

	oct = tvb_get_guint8(tvb, curr_offset);

	switch(oct)
	{
		case 0: str="704"; break;
		case 65: str="71"; break;
		case 66: str="72"; break;
		case 67: str="74"; break;
		case 68: str="75"; break;
		case 69: str="77"; break;
		case 70: str="79"; break;
		case 71: str="80"; break;
		case 72: str="83"; break;
		case 73: str="86"; break;
		case 74: str="88"; break;
		case 75: str="90"; break;
		case 76: str="92"; break;
		case 77: str="96"; break;
		case 78: str="101"; break;
		case 79: str="103"; break;
		case 80: str="107"; break;
		case 81: str="112"; break;
		case 82: str="116"; break;
		case 83: str="118"; break;
		case 84: str="128"; break;
		case 85: str="141"; break;
		case 86: str="144"; break;
		case 87: str="150"; break;
		case 88: str="160"; break;
		case 89: str="171"; break;
		case 90: str="176"; break;
		case 91: str="192"; break;
		case 92: str="214"; break;
		case 93: str="224"; break;
		case 94: str="235"; break;
		case 95: str="256"; break;
		case 96: str="288"; break;
		case 97: str="320"; break;
		case 98: str="352"; break;
	default:
		str_val[0]=oct/10+'0';
		str_val[1]=oct%10+'0';
		str_val[2]=0;
		str=str_val;
	}

	proto_tree_add_text(tf_tree,
		tvb, curr_offset, 1,
		"Split PG Cycle Code: (%u) %s",
		oct,
		str);

	curr_offset++;
	proto_tree_add_item(tf_tree, hf_gsm_a_gmm_cn_spec_drs_cycle_len_coef, tvb, curr_offset, 1, FALSE);
	proto_tree_add_item(tf_tree, hf_gsm_a_gmm_split_on_ccch, tvb, curr_offset, 1, FALSE);
	proto_tree_add_item(tf_tree, hf_gsm_a_gmm_non_drx_timer, tvb, curr_offset, 1, FALSE);

	curr_offset++;

	/* no length check possible */

	return(curr_offset - offset);
}

/*
 * [7] 10.5.5.7
 */
static guint16
de_gmm_ftostby(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint8	oct;
	guint32	curr_offset;
	const gchar	*str;

	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	switch(oct&7)
	{
		case 1: str="Force to standby indicated"; break;
		default: str="force to standby not indicated";
	}

	proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"Force to Standby: (%u) %s",
		oct&7,
		str);

	curr_offset++;

	/* no length check possible */

	return(curr_offset - offset);
}

/*
 * [7] 10.5.5.7
 */
static guint16
de_gmm_ftostby_h(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint8	oct;
	guint32	curr_offset;
	const gchar	*str;

	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	/* IMPORTANT - IT'S ASSUMED THAT THE INFORMATION IS IN THE HIGHER NIBBLE */
	oct >>= 4;

	switch(oct&7)
	{
		case 1: str="Force to standby indicated"; break;
		default: str="force to standby not indicated";
	}

	proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"Force to Standby: (%u) %s",
		oct&7,
		str);

	curr_offset++;

	/* no length check possible */

	return(curr_offset - offset);
}

/*
 * [7] 10.5.5.8
 */
static guint16
de_gmm_ptmsi_sig(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;
	proto_item 	*curr_item;

	curr_offset = offset;
	
	curr_item= proto_tree_add_item(tree,hf_gsm_a_ptmsi_sig,tvb,curr_offset,3,FALSE);
	proto_item_append_text(curr_item,"%s",add_string ? add_string : "");

	curr_offset+=3;

	/* no length check possible */

	return(curr_offset - offset);
}

/*
 * [7] 10.5.5.8a
 */
static guint16
de_gmm_ptmsi_sig2(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len _U_)
{
	guint32	curr_offset;
	proto_item	*curr_item;

	curr_offset = offset;

	curr_item= proto_tree_add_item(tree,hf_gsm_a_ptmsi_sig2,tvb,curr_offset,3,FALSE);
	proto_item_append_text(curr_item,"%s",add_string ? add_string : "");
	curr_offset+=3;

	EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

	return(curr_offset - offset);
}

/*
 * [7] 10.5.5.9
 */
static guint16
de_gmm_ident_type2(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint8	oct;
	guint32	curr_offset;
	const gchar	*str;

	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	switch ( oct&7 )
	{
		case 2: str="IMEI"; break;
		case 3: str="IMEISV"; break;
		case 4: str="TMSI"; break;
		default: str="IMSI";
	}

	proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"Identity Type 2: (%u) %s",
		oct&7,
		str);

	curr_offset++;

	/* no length check possible */

	return(curr_offset - offset);
}

/*
 * [7] 10.5.5.10
 */
static guint16
de_gmm_imeisv_req(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint8	oct;
	guint32	curr_offset;
	const gchar	*str;

	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	/* IMPORTANT - IT'S ASSUMED THAT THE INFORMATION IS IN THE HIGHER NIBBLE */
	oct >>= 4;

	switch ( oct&7 )
	{
		case 1: str="IMEISV requested"; break;
		default: str="IMEISV not requested";
	}

	proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"IMEISV Request: (%u) %s",
		oct&7,
		str);

	curr_offset++;

	/* no length check possible */

	return(curr_offset - offset);
}

/*
 * [7] 10.5.5.11
 */
static guint16
de_gmm_rec_npdu_lst(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;
	guint	curr_len;

	curr_len = len;
	curr_offset = offset;

	if ( len == 0 ) return 0;

	do
	{
		guint32	oct;
		oct = tvb_get_guint8(tvb, curr_offset);
		oct <<=8;
		oct |= tvb_get_guint8(tvb, curr_offset+1);
		curr_len -= 2;
		oct <<=8;

		proto_tree_add_text(tree,
			tvb, curr_offset, 2,
			"NSAPI %d: 0x%02x (%u)",
			oct>>20,
			(oct>>12)&0xff,
			(oct>>12)&0xff);
		curr_offset+= 2;

		if ( curr_len > 2 )
		{
			oct |= tvb_get_guint8(tvb, curr_offset+2);
			curr_len--;
			oct <<= 12;

			proto_tree_add_text(tree,
				tvb, curr_offset-1, 2,
				"NSAPI %d: 0x%02x (%u)",
				oct>>20,
				(oct>>12)&0xff,
				(oct>>12)&0xff);
			curr_offset++;
		}

	} while ( curr_len > 1 );

	EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

	return(curr_offset - offset);
}

/*
 * [7] 10.5.5.12
 */
guint16
de_gmm_ms_net_cap(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint8	oct;
	guint32	curr_offset;
	guint	curr_len;
	guint	gea_val;

	gchar answer_gea[2][40]={ "encryption algorithm not available",
				"encryption algorithm available" };
	gchar answer_smdch[2][120]={ "Mobile station does not support mobile terminated point to point SMS via dedicated signalling channels",
				"Mobile station supports mobile terminated point to point SMS via dedicated signalling channels" };
	gchar answer_smgprs[2][100]={ "Mobile station does not support mobile terminated point to point SMS via GPRS packet data channels",
				"Mobile station supports mobile terminated point to point SMS via GPRS packet data channels" };
	gchar answer_ucs2[2][100]={ "the ME has a preference for the default alphabet (defined in 3GPP TS 23.038 [8b]) over UCS2",
				"the ME has no preference between the use of the default alphabet and the use of UCS2" };

	gchar answer_ssid[4][80]={ "default value of phase 1",
				"capability of handling of ellipsis notation and phase 2 error handling",
				"capability of handling of ellipsis notation and phase 2 error handling",
				"capability of handling of ellipsis notation and phase 2 error handling" };

	gchar answer_solsa[2][40]={ "The ME does not support SoLSA",
				"The ME supports SoLSA" };
			
	gchar answer_rev[2][80]={ "used by a mobile station not supporting R99 or later versions of the protocol",
				"used by a mobile station supporting R99 or later versions of the protocol" };

	gchar answer_pfc[2][80]={ "Mobile station does not support BSS packet flow procedures",
				"Mobile station does support BSS packet flow procedures" };

	gchar answer_lcs[2][80]={ "LCS value added location request notification capability not supported" ,
				"LCS value added location request notification capability supported" };

	curr_len = len;
	curr_offset = offset;

	if ( curr_len == 0 ){ EXTRANEOUS_DATA_CHECK(len, curr_offset - offset); return(curr_offset - offset); }
	oct = tvb_get_guint8(tvb, curr_offset);
	curr_len--;

	/* bit 8 */
	proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"GEA1: (%u) %s",
		oct>>7,
		answer_gea[oct>>7]);
	oct<<=1;

	/* bit 7 */
	proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"SM capabilities via dedicated channels: (%u) %s",
		oct>>7,
		answer_smdch[oct>>7]);
	oct<<=1;

	/* bit 6 */
	proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"SM capabilities via GPRS channels: (%u) %s",
		oct>>7,
		answer_smgprs[oct>>7]);
	oct<<=1;

	/* bit 5 */
	proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"UCS2 support: (%u) %s",
		oct>>7,
		answer_ucs2[oct>>7]);
	oct<<=1;

	/* bit 4 3 */
	proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"SS Screening Indicator: (%u) %s",
		oct>>6,
		answer_ssid[oct>>6]);
	oct<<=2;

	/* bit 2 */
	proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"SoLSA Capability: (%u) %s",
		oct>>7,
		answer_solsa[oct>>7]);
	oct<<=1;

	/* bit 1 */
	proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"Revision level indicator: (%u) %s",
		oct>>7,
		answer_rev[oct>>7]);

	curr_offset++;

	if ( curr_len == 0 ){ EXTRANEOUS_DATA_CHECK(len, curr_offset - offset); return(curr_offset - offset); }
	oct = tvb_get_guint8(tvb, curr_offset);
	curr_len--;

	proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"PFC feature mode: (%u) %s",
		oct>>7,
		answer_pfc[oct>>7]);
	oct<<=1;

	for( gea_val=2; gea_val<8 ; gea_val++ )
	{
		proto_tree_add_text(tree,
			tvb, curr_offset, 1,
			"GEA%d: (%u) %s", gea_val,
			oct>>7,
			answer_gea[oct>>7]);
		oct<<=1;
	}

	proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"LCS VA capability:: (%u) %s",
		oct>>7,
		answer_lcs[oct>>7]);

	curr_offset++;
	   
	EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

	return(curr_offset - offset);
}

/*
 * [7] 10.5.5.12a
 */
#define GET_DATA				/* check if we have enough bits left */ \
	if ( curr_bits_length < bits_needed ) \
		continue; \
	/* check if oct has enougth bits */ \
	if ( bits_in_oct < bits_needed ) \
	{ \
		guint32 tmp_oct; \
		if ( curr_len == 0 ) \
		{ \
			proto_tree_add_text(tf_tree, \
				tvb, curr_offset, 1, \
				"Not enough data available"); \
		} \
		tmp_oct = tvb_get_guint8(tvb, curr_offset); \
		oct |= tmp_oct<<(32-8-bits_in_oct); \
		curr_len--; \
		curr_offset++; \
		if ( bits_in_oct != 0 ) \
			add_ocetets = 1; \
		else \
			add_ocetets = 0; \
		bits_in_oct += 8; \
	} \
	else \
		add_ocetets = 0;

guint16
de_gmm_ms_radio_acc_cap(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint32     curr_offset;
	guint       curr_len;
	proto_item  *tf = NULL;
	proto_tree  *tf_tree = NULL;
	guint32     oct;
	guchar      bits_in_oct;
	guchar      bits_needed;
	guint       bits_length;
	guint       add_ocetets;	/* octets which are covered by one element -1 */
	guint       curr_bits_length;
	guchar      acc_type;
	const gchar *str;
	gchar       multi_slot_str[64][230] = {
		"Not specified", /* 00 */
		"Max Rx-Slot/TDMA:1 Max Tx-Slot/TDMA:1 Max-Sum-Slot/TDMA:2 Tta:3 Ttb:2 Tra:4 Trb:2 Type:1", /* 01 */
		"Max Rx-Slot/TDMA:2 Max Tx-Slot/TDMA:1 Max-Sum-Slot/TDMA:3 Tta:3 Ttb:2 Tra:3 Trb:1 Type:1", /* 02 */
		"Max Rx-Slot/TDMA:2 Max Tx-Slot/TDMA:2 Max-Sum-Slot/TDMA:3 Tta:3 Ttb:2 Tra:3 Trb:1 Type:1", /* 03 */
		"Max Rx-Slot/TDMA:3 Max Tx-Slot/TDMA:1 Max-Sum-Slot/TDMA:4 Tta:3 Ttb:1 Tra:3 Trb:1 Type:1", /* 04 */
		"Max Rx-Slot/TDMA:2 Max Tx-Slot/TDMA:2 Max-Sum-Slot/TDMA:4 Tta:3 Ttb:1 Tra:3 Trb:1 Type:1", /* 05 */
		"Max Rx-Slot/TDMA:3 Max Tx-Slot/TDMA:2 Max-Sum-Slot/TDMA:4 Tta:3 Ttb:1 Tra:3 Trb:1 Type:1", /* 06 */
		"Max Rx-Slot/TDMA:3 Max Tx-Slot/TDMA:3 Max-Sum-Slot/TDMA:4 Tta:3 Ttb:1 Tra:3 Trb:1 Type:1", /* 07 */
		"Max Rx-Slot/TDMA:4 Max Tx-Slot/TDMA:1 Max-Sum-Slot/TDMA:5 Tta:3 Ttb:1 Tra:2 Trb:1 Type:1", /* 08 */
		"Max Rx-Slot/TDMA:3 Max Tx-Slot/TDMA:2 Max-Sum-Slot/TDMA:5 Tta:3 Ttb:1 Tra:2 Trb:1 Type:1", /* 09 */
		"Max Rx-Slot/TDMA:4 Max Tx-Slot/TDMA:2 Max-Sum-Slot/TDMA:5 Tta:3 Ttb:1 Tra:2 Trb:1 Type:1", /* 10 */
		"Max Rx-Slot/TDMA:4 Max Tx-Slot/TDMA:3 Max-Sum-Slot/TDMA:5 Tta:3 Ttb:1 Tra:2 Trb:1 Type:1", /* 11 */
		"Max Rx-Slot/TDMA:4 Max Tx-Slot/TDMA:4 Max-Sum-Slot/TDMA:5 Tta:2 Ttb:1 Tra:2 Trb:1 Type:1", /* 12 */
		"Max Rx-Slot/TDMA:3 Max Tx-Slot/TDMA:3 Max-Sum-Slot/TDMA:NA Tta:NA Ttb:a) Tra:3 Trb:a) Type:2 (a: 1 with frequency hopping, 0 otherwise)", /* 13 */
		"Max Rx-Slot/TDMA:4 Max Tx-Slot/TDMA:4 Max-Sum-Slot/TDMA:NA Tta:NA Ttb:a) Tra:3 Trb:a) Type:2 (a: 1 with frequency hopping, 0 otherwise)", /* 14 */
		"Max Rx-Slot/TDMA:5 Max Tx-Slot/TDMA:5 Max-Sum-Slot/TDMA:NA Tta:NA Ttb:a) Tra:3 Trb:a) Type:2 (a: 1 with frequency hopping, 0 otherwise)", /* 15 */
		"Max Rx-Slot/TDMA:6 Max Tx-Slot/TDMA:6 Max-Sum-Slot/TDMA:NA Tta:NA Ttb:a) Tra:2 Trb:a) Type:2 (a: 1 with frequency hopping, 0 otherwise)", /* 16 */
		"Max Rx-Slot/TDMA:7 Max Tx-Slot/TDMA:7 Max-Sum-Slot/TDMA:NA Tta:NA Ttb:a) Tra:1 Trb:0 Type:2 (a: 1 with frequency hopping, 0 otherwise)", /* 17 */
		"Max Rx-Slot/TDMA:8 Max Tx-Slot/TDMA:8 Max-Sum-Slot/TDMA:NA Tta:NA Ttb:0 Tra:0 Trb:0 Type:2", /* 18 */
		"Max Rx-Slot/TDMA:6 Max Tx-Slot/TDMA:2 Max-Sum-Slot/TDMA:NA Tta:3 Ttb:b) Tra:2 Trb:c) Type:1 (b: 1 with frequency hopping or change from Rx to Tx, 0 otherwise; c: 1 with frequency hopping or change from Tx to Rx, 0 otherwise", /* 19 */   
		"Max Rx-Slot/TDMA:6 Max Tx-Slot/TDMA:3 Max-Sum-Slot/TDMA:NA Tta:3 Ttb:b) Tra:2 Trb:c) Type:1 (b: 1 with frequency hopping or change from Rx to Tx, 0 otherwise; c: 1 with frequency hopping or change from Tx to Rx, 0 otherwise", /* 20 */
		"Max Rx-Slot/TDMA:6 Max Tx-Slot/TDMA:4 Max-Sum-Slot/TDMA:NA Tta:3 Ttb:b) Tra:2 Trb:c) Type:1 (b: 1 with frequency hopping or change from Rx to Tx, 0 otherwise; c: 1 with frequency hopping or change from Tx to Rx, 0 otherwise", /* 21 */
		"Max Rx-Slot/TDMA:6 Max Tx-Slot/TDMA:4 Max-Sum-Slot/TDMA:NA Tta:3 Ttb:b) Tra:2 Trb:c) Type:1 (b: 1 with frequency hopping or change from Rx to Tx, 0 otherwise; c: 1 with frequency hopping or change from Tx to Rx, 0 otherwise", /* 22 */
		"Max Rx-Slot/TDMA:6 Max Tx-Slot/TDMA:6 Max-Sum-Slot/TDMA:NA Tta:3 Ttb:b) Tra:2 Trb:c) Type:1 (b: 1 with frequency hopping or change from Rx to Tx, 0 otherwise; c: 1 with frequency hopping or change from Tx to Rx, 0 otherwise", /* 23 */
		"Max Rx-Slot/TDMA:8 Max Tx-Slot/TDMA:2 Max-Sum-Slot/TDMA:NA Tta:3 Ttb:b) Tra:2 Trb:c) Type:1 (b: 1 with frequency hopping or change from Rx to Tx, 0 otherwise; c: 1 with frequency hopping or change from Tx to Rx, 0 otherwise", /* 24 */
		"Max Rx-Slot/TDMA:8 Max Tx-Slot/TDMA:3 Max-Sum-Slot/TDMA:NA Tta:3 Ttb:b) Tra:2 Trb:c) Type:1 (b: 1 with frequency hopping or change from Rx to Tx, 0 otherwise; c: 1 with frequency hopping or change from Tx to Rx, 0 otherwise", /* 25 */
		"Max Rx-Slot/TDMA:8 Max Tx-Slot/TDMA:4 Max-Sum-Slot/TDMA:NA Tta:3 Ttb:b) Tra:2 Trb:c) Type:1 (b: 1 with frequency hopping or change from Rx to Tx, 0 otherwise; c: 1 with frequency hopping or change from Tx to Rx, 0 otherwise", /* 26 */
		"Max Rx-Slot/TDMA:8 Max Tx-Slot/TDMA:4 Max-Sum-Slot/TDMA:NA Tta:3 Ttb:b) Tra:2 Trb:c) Type:1 (b: 1 with frequency hopping or change from Rx to Tx, 0 otherwise; c: 1 with frequency hopping or change from Tx to Rx, 0 otherwise", /* 27 */
		"Max Rx-Slot/TDMA:8 Max Tx-Slot/TDMA:6 Max-Sum-Slot/TDMA:NA Tta:3 Ttb:b) Tra:2 Trb:c) Type:1 (b: 1 with frequency hopping or change from Rx to Tx, 0 otherwise; c: 1 with frequency hopping or change from Tx to Rx, 0 otherwise", /* 28 */
		"Max Rx-Slot/TDMA:8 Max Tx-Slot/TDMA:8 Max-Sum-Slot/TDMA:NA Tta:3 Ttb:b) Tra:2 Trb:c) Type:1 (b: 1 with frequency hopping or change from Rx to Tx, 0 otherwise; c: 1 with frequency hopping or change from Tx to Rx, 0 otherwise", /* 29 */
		"Max Rx-Slot/TDMA:5 Max Tx-Slot/TDMA:1 Max-Sum-Slot/TDMA:6 Tta:2 Ttb:1 Tra:1 Trb:1 Type:1", /* 30 */
		"Max Rx-Slot/TDMA:5 Max Tx-Slot/TDMA:2 Max-Sum-Slot/TDMA:6 Tta:2 Ttb:1 Tra:1 Trb:1 Type:1", /* 31 */
		"Max Rx-Slot/TDMA:5 Max Tx-Slot/TDMA:3 Max-Sum-Slot/TDMA:6 Tta:2 Ttb:1 Tra:1 Trb:1 Type:1", /* 32 */
		"Max Rx-Slot/TDMA:5 Max Tx-Slot/TDMA:4 Max-Sum-Slot/TDMA:6 Tta:2 Ttb:1 Tra:1 Trb:1 Type:1", /* 33 */
		"Max Rx-Slot/TDMA:5 Max Tx-Slot/TDMA:5 Max-Sum-Slot/TDMA:6 Tta:2 Ttb:1 Tra:1 Trb:1 Type:1", /* 34 */
	   	"Max Rx-Slot/TDMA:5 Max Tx-Slot/TDMA:1 Max-Sum-Slot/TDMA:6 Tta:2 Ttb:1 Tra:1+to Trb:1 Type:1 (to: to = 31 symbol periods (this can be provided by a TA offset, i.e. a minimum TA value))", /* 35 */
		"Max Rx-Slot/TDMA:5 Max Tx-Slot/TDMA:2 Max-Sum-Slot/TDMA:6 Tta:2 Ttb:1 Tra:1+to Trb:1 Type:1 (to: to = 31 symbol periods (this can be provided by a TA offset, i.e. a minimum TA value))", /* 36 */
		"Max Rx-Slot/TDMA:5 Max Tx-Slot/TDMA:3 Max-Sum-Slot/TDMA:6 Tta:2 Ttb:1 Tra:1+to Trb:1 Type:1 (to: to = 31 symbol periods (this can be provided by a TA offset, i.e. a minimum TA value))", /* 37 */
		"Max Rx-Slot/TDMA:5 Max Tx-Slot/TDMA:4 Max-Sum-Slot/TDMA:6 Tta:2 Ttb:1 Tra:1+to Trb:1 Type:1 (to: to = 31 symbol periods (this can be provided by a TA offset, i.e. a minimum TA value))", /* 38 */
		"Max Rx-Slot/TDMA:5 Max Tx-Slot/TDMA:5 Max-Sum-Slot/TDMA:6 Tta:2 Ttb:1 Tra:1+to Trb:1 Type:1 (to: to = 31 symbol periods (this can be provided by a TA offset, i.e. a minimum TA value))", /* 39 */
		"Max Rx-Slot/TDMA:6 Max Tx-Slot/TDMA:1 Max-Sum-Slot/TDMA:7 Tta:1 Ttb:1 Tra:1 Trb:to Type:1 (to: to = 31 symbol periods (this can be provided by a TA offset, i.e. a minimum TA value))", /* 40 */
		"Max Rx-Slot/TDMA:6 Max Tx-Slot/TDMA:2 Max-Sum-Slot/TDMA:7 Tta:1 Ttb:1 Tra:1 Trb:to Type:1 (to: to = 31 symbol periods (this can be provided by a TA offset, i.e. a minimum TA value))", /* 41 */
		"Max Rx-Slot/TDMA:6 Max Tx-Slot/TDMA:3 Max-Sum-Slot/TDMA:7 Tta:1 Ttb:1 Tra:1 Trb:to Type:1 (to: to = 31 symbol periods (this can be provided by a TA offset, i.e. a minimum TA value))", /* 42 */
		"Max Rx-Slot/TDMA:6 Max Tx-Slot/TDMA:4 Max-Sum-Slot/TDMA:7 Tta:1 Ttb:1 Tra:1 Trb:to Type:1 (to: to = 31 symbol periods (this can be provided by a TA offset, i.e. a minimum TA value))", /* 43 */
		"Max Rx-Slot/TDMA:6 Max Tx-Slot/TDMA:5 Max-Sum-Slot/TDMA:7 Tta:1 Ttb:1 Tra:1 Trb:to Type:1 (to: to = 31 symbol periods (this can be provided by a TA offset, i.e. a minimum TA value))", /* 44 */
		"Max Rx-Slot/TDMA:6 Max Tx-Slot/TDMA:6 Max-Sum-Slot/TDMA:7 Tta:1 Ttb:1 Tra:1 Trb:to Type:1 (to: to = 31 symbol periods (this can be provided by a TA offset, i.e. a minimum TA value))", /* 45 */
		"Not specified", /* 46 */
		"Not specified", /* 47 */
		"Not specified", /* 48 */
		"Not specified", /* 49 */
		"Not specified", /* 50 */
		"Not specified", /* 51 */
		"Not specified", /* 52 */
		"Not specified", /* 53 */
		"Not specified", /* 54 */
		"Not specified", /* 55 */
		"Not specified", /* 56 */
		"Not specified", /* 57 */
		"Not specified", /* 58 */
		"Not specified", /* 59 */
		"Not specified", /* 60 */
		"Not specified", /* 61 */
		"Not specified", /* 62 */
		"Not specified", /* 63 */
	};
	guint indx = 0;
	guchar dtm_gprs_mslot = 0;
	guchar dtm_egprs_mslot = 4;
	gboolean finished = TRUE;

	curr_len = len;
	curr_offset = offset;

	bits_in_oct = 0;
	oct = 0;

	do
	{
		/* check for a new round */
		if (( curr_len*8 + bits_in_oct ) < 11 )
			break;

		/* now read the first 11 bits */
		curr_bits_length = 11;
		/*
		 *
		 */
		if ( curr_len != len )
		{
			bits_needed = 1;
			GET_DATA;

			if (( oct>>(32-bits_needed) ) == 1 )
			{
				curr_bits_length -= bits_needed;
				oct <<= bits_needed;
				bits_in_oct -= bits_needed;
			
				if (( curr_len*8 + bits_in_oct ) < 11 )
					break;
				curr_bits_length = 11;
			}
			else
			{
				curr_bits_length -= bits_needed;
				oct <<= bits_needed;
				bits_in_oct -= bits_needed;
				break;
			}
		}

		indx++;
		tf = proto_tree_add_text(tree,
				tvb, curr_offset, 1,
				"MS RA capability %d",indx);

		tf_tree = proto_item_add_subtree(tf, ett_gmm_radio_cap );

		/*
		 * Access Technology
		 */
		bits_needed = 4;
		GET_DATA;

		acc_type = oct>>(32-bits_needed);
		switch ( acc_type )
		{
			case 0x00: str="GSM P"; break;
			case 0x01: str="GSM E --note that GSM E covers GSM P"; break;
			case 0x02: str="GSM R --note that GSM R covers GSM E and GSM P"; break;
			case 0x03: str="GSM 1800"; break;
			case 0x04: str="GSM 1900"; break;
			case 0x05: str="GSM 450"; break;
			case 0x06: str="GSM 480"; break;
			case 0x07: str="GSM 850"; break;
			case 0x08: str="GSM 700"; break;
			case 0x0f: str="Indicates the presence of a list of Additional access technologies"; break;
			default: str="unknown";
		}

		proto_tree_add_text(tf_tree,
			tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
			"Access Technology Type: (%u) %s",acc_type,str);
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;

		/*
		 * get bits_length
		 */
		bits_needed = 7;
		GET_DATA;

		bits_length = curr_bits_length = oct>>(32-bits_needed);
		proto_tree_add_text(tf_tree,
			tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
			"Length: 0x%02x bits (%u)",bits_length,bits_length);
		/* This is already done - length doesn't contain this field
		 curr_bits_length -= bits_needed;
		*/
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;

		if ( acc_type == 0x0f )
		{
			do
			{
				/*
				 * Additional access technologies:
				 */
				finished = TRUE; /* Break out of the loop unless proven unfinished */

				/*
				 * Presence bit
				 */
				bits_needed = 1;
				GET_DATA;

				/* analyse bits */
				switch ( oct>>(32-bits_needed) )
				{
					case 0x00: str="Not Present"; finished = TRUE; break;
					case 0x01: str="Present"; finished = FALSE; break;
					default: str="This should not happen";
				}

				proto_tree_add_text(tf_tree,
					tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
					"Presence: (%u) %s",oct>>(32-bits_needed),str);
				curr_bits_length -= bits_needed;
				oct <<= bits_needed;
				bits_in_oct -= bits_needed;

				if (finished)
				{
					/*
					 * No more valid data, get spare bits if any
					 */
					while ( curr_bits_length > 0 )
					{
						if ( curr_bits_length > 8 )
							bits_needed = 8;
						else
							bits_needed = curr_bits_length;
						GET_DATA;
						curr_bits_length -= bits_needed;
						oct <<= bits_needed;
						bits_in_oct -= bits_needed;
					}
					continue;
				}

				/*
				 * Access Technology
				 */
				bits_needed = 4;
				GET_DATA;

				acc_type = oct>>(32-bits_needed);
				switch ( acc_type )
				{
					case 0x00: str="GSM P"; break;
					case 0x01: str="GSM E --note that GSM E covers GSM P"; break;
					case 0x02: str="GSM R --note that GSM R covers GSM E and GSM P"; break;
					case 0x03: str="GSM 1800"; break;
					case 0x04: str="GSM 1900"; break;
					case 0x05: str="GSM 450"; break;
					case 0x06: str="GSM 480"; break;
					case 0x07: str="GSM 850"; break;
					case 0x08: str="GSM 700"; break;
					case 0x0f: str="Indicates the presence of a list of Additional access technologies"; break;
					default: str="unknown";
				}

				proto_tree_add_text(tf_tree,
					tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
					"Access Technology Type: (%u) %s",acc_type,str);
				curr_bits_length -= bits_needed;
				oct <<= bits_needed;
				bits_in_oct -= bits_needed;

				/*
				 * RF Power
				 */
				bits_needed = 3;
				GET_DATA;

				/* analyse bits */
				if ( acc_type == 0x04 )	/* GSM 1900 */
				{
					switch ( oct>>(32-bits_needed) )
					{
						case 0x01: str="1 W (30 dBm)"; break;
						case 0x02: str="0,25 W (24 dBm)"; break;
						case 0x03: str="2 W (33 dBm)"; break;
						default: str="Not specified";
					}
				}
				else if ( acc_type == 0x03 )
				{
					switch ( oct>>(32-bits_needed) )
					{
						case 0x01: str="1 W (30 dBm)"; break;
						case 0x02: str="0,25 W (24 dBm)"; break;
						case 0x03: str="4 W (36 dBm)"; break;
						default: str="Not specified";
					}
				}
				else if ( acc_type <= 0x08 )
				{
					switch ( oct>>(32-bits_needed) )
					{
						case 0x02: str="8 W (39 dBm)"; break;
						case 0x03: str="5 W (37 dBm)"; break;
						case 0x04: str="2 W (33 dBm)"; break;
						case 0x05: str="0,8 W (29 dBm)"; break;
						default: str="Not specified";
					}
				}
				else
					str="Not specified??";

				proto_tree_add_text(tf_tree,
					tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
					"RF Power Capability, GMSK Power Class: (%u) %s",oct>>(32-bits_needed),str);
				curr_bits_length -= bits_needed;
				oct <<= bits_needed;
				bits_in_oct -= bits_needed;

				/*
				 * 8PSK Power Class
				 */
				bits_needed = 2;
				GET_DATA;

				/* analyse bits */
				switch ( oct>>(32-bits_needed) )
				{
					case 0x00: str="8PSK modulation not supported for uplink"; break;
					case 0x01: str="Power class E1"; break;
					case 0x02: str="Power class E2"; break;
					case 0x03: str="Power class E3"; break;
					default: str="This should not happen";
				}

				proto_tree_add_text(tf_tree,
					tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
					"8PSK Power Class: (%u) %s",oct>>(32-bits_needed),str);
				curr_bits_length -= bits_needed;
				oct <<= bits_needed;
				bits_in_oct -= bits_needed;

			} while (!finished);

			/* goto next one */
			continue;
		}
		/*
		 * RF Power
		 */
		bits_needed = 3;
		GET_DATA;

		/* analyse bits */
		if ( acc_type == 0x04 )	/* GSM 1900 */
		{
			switch ( oct>>(32-bits_needed) )
			{
				case 0x01: str="1 W (30 dBm)"; break;
				case 0x02: str="0,25 W (24 dBm)"; break;
				case 0x03: str="2 W (33 dBm)"; break;
				default: str="Not specified";
			}
		}
		else if ( acc_type == 0x03 )
		{
			switch ( oct>>(32-bits_needed) )
			{
				case 0x01: str="1 W (30 dBm)"; break;
				case 0x02: str="0,25 W (24 dBm)"; break;
				case 0x03: str="4 W (36 dBm)"; break;
				default: str="Not specified";
			}
		}
		else if ( acc_type <= 0x08 )
		{
			switch ( oct>>(32-bits_needed) )
			{
				case 0x02: str="8 W (39 dBm)"; break;
				case 0x03: str="5 W (37 dBm)"; break;
				case 0x04: str="2 W (33 dBm)"; break;
				case 0x05: str="0,8 W (29 dBm)"; break;
				default: str="Not specified";
			}
		}
		else
			str="Not specified??";

		proto_tree_add_text(tf_tree,
			tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
			"RF Power Capability, GMSK Power Class: (%u) %s",oct>>(32-bits_needed),str);
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;

		/*
		 * A5 Bits?
		 */
		bits_needed = 1;
		GET_DATA;

		/* analyse bits */
		if ((oct>>(32-bits_needed))==0)
		{
			proto_tree_add_text(tf_tree,
				tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
				"A5 Bits: (%u) same values apply for parameters as in the immediately preceding Access capabilities field within this IE",oct>>(32-bits_needed));
			curr_bits_length -= bits_needed;
			oct <<= bits_needed;
			bits_in_oct -= bits_needed;
		}
		else
		{
			int i;

			proto_tree_add_text(tf_tree,
				tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
				"A5 Bits: (%u) A5 bits follows",oct>>(32-bits_needed));

			curr_bits_length -= bits_needed;
			oct <<= bits_needed;
			bits_in_oct -= bits_needed;
		
			for (i=1; i<= 7 ; i++ )
			{
				/*
				 * A5 Bits decoding
				 */
				bits_needed = 1;
				GET_DATA;

				/* analyse bits */
				switch ( oct>>(32-bits_needed) )
				{
					case 0x00: str="encryption algorithm not available"; break;
					case 0x01: str="encryption algorithm available"; break;
					default: str="This should not happen";
				}

				proto_tree_add_text(tf_tree,
					tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
					"A5/%d: (%u) %s",i,oct>>(32-bits_needed),str);
				curr_bits_length -= bits_needed;
				oct <<= bits_needed;
				bits_in_oct -= bits_needed;
			}
		}

		/*
		 * ES IND
		 */
		bits_needed = 1;
		GET_DATA;

		/* analyse bits */
		switch ( oct>>(32-bits_needed) )
		{
			case 0x00: str="controlled early Classmark Sending option is not implemented"; break;
			case 0x01: str="controlled early Classmark Sending option is implemented"; break;
			default: str="This should not happen";
		}

		proto_tree_add_text(tf_tree,
			tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
			"Controlled early Classmark Sending: (%u) %s",oct>>(32-bits_needed),str);
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;

		/*
		 * PS
		 */
		bits_needed = 1;
		GET_DATA;

		/* analyse bits */
		switch ( oct>>(32-bits_needed) )
		{
			case 0x00: str="PS capability not present"; break;
			case 0x01: str="PS capability present"; break;
			default: str="This should not happen";
		}

		proto_tree_add_text(tf_tree,
			tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
			"Pseudo Synchronisation: (%u) %s",oct>>(32-bits_needed),str);
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;

		/*
		 * VGCS
		 */
		bits_needed = 1;
		GET_DATA;

		/* analyse bits */
		switch ( oct>>(32-bits_needed) )
		{
			case 0x00: str="no VGCS capability or no notifications wanted"; break;
			case 0x01: str="VGCS capability and notifications wanted"; break;
			default: str="This should not happen";
		}

		proto_tree_add_text(tf_tree,
			tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
			"Voice Group Call Service: (%u) %s",oct>>(32-bits_needed),str);
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;

		/*
		 * VBS
		 */
		bits_needed = 1;
		GET_DATA;

		/* analyse bits */
		switch ( oct>>(32-bits_needed) )
		{
			case 0x00: str="no VBS capability or no notifications wanted"; break;
			case 0x01: str="VBS capability and notifications wanted"; break;
			default: str="This should not happen";
		}

		proto_tree_add_text(tf_tree,
			tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
			"Voice Broadcast Service: (%u) %s",oct>>(32-bits_needed),str);
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;

		/*
		 * Multislot capability?
		 */
		bits_needed = 1;
		GET_DATA;

		/* analyse bits */
		if ((oct>>(32-bits_needed))==0)
		{
			proto_tree_add_text(tf_tree,
				tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
				"Multislot capability: (%u) same values apply for parameters as in the immediately preceding Access capabilities field within this IE",oct>>(32-bits_needed));
			curr_bits_length -= bits_needed;
			oct <<= bits_needed;
			bits_in_oct -= bits_needed;
		}
		else
		{
			proto_tree_add_text(tf_tree,
			tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
			"Multislot capability: (%u) Multislot capability struct available",oct>>(32-bits_needed));

			curr_bits_length -= bits_needed;
			oct <<= bits_needed;
			bits_in_oct -= bits_needed;

			/*
			 * HSCSD multislot class?
			 */
			bits_needed = 1;
			GET_DATA;

			/* analyse bits */
			if ((oct>>(32-bits_needed))==0)
			{
				proto_tree_add_text(tf_tree,
					tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
					"HSCSD multislot class: (%u) Bits are not available",oct>>(32-bits_needed));
				curr_bits_length -= bits_needed;
				oct <<= bits_needed;
				bits_in_oct -= bits_needed;
			}
			else
			{
				curr_bits_length -= bits_needed;
				oct <<= bits_needed;
				bits_in_oct -= bits_needed;

				/*
				 * HSCSD multislot class
				 */
				bits_needed = 5;
				GET_DATA;

				/* analyse bits */
				proto_tree_add_text(tf_tree,
					tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
					"HSCSD multislot class: (%u) %s",oct>>(32-bits_needed),multi_slot_str[oct>>(32-bits_needed)]);
				curr_bits_length -= bits_needed;
				oct <<= bits_needed;
				bits_in_oct -= bits_needed;
			}

			/*
			 * GPRS multislot class?
			 */
			bits_needed = 1;
			GET_DATA;

			/* analyse bits */
			if ((oct>>(32-bits_needed))==0)
			{
				proto_tree_add_text(tf_tree,
					tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
					"GPRS multislot class: (%u) Bits are not available",oct>>(32-bits_needed));
				curr_bits_length -= bits_needed;
				oct <<= bits_needed;
				bits_in_oct -= bits_needed;
			}
			else
			{
				curr_bits_length -= bits_needed;
				oct <<= bits_needed;
				bits_in_oct -= bits_needed;

				/*
				 * GPRS multislot class
				 */
				bits_needed = 5;
				GET_DATA;

				/* analyse bits */
				proto_tree_add_text(tf_tree,
					tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
					"GPRS multislot class: (%u) %s",oct>>(32-bits_needed),multi_slot_str[oct>>(32-bits_needed)]);
				curr_bits_length -= bits_needed;
				oct <<= bits_needed;
				bits_in_oct -= bits_needed;

				/*
				 * GPRS Extended Dynamic Allocation Capability
				 */
				bits_needed = 1;
				GET_DATA;

				/* analyse bits */
				switch ( oct>>(32-bits_needed) )
				{
					case 0x00: str="Extended Dynamic Allocation Capability for GPRS is not implemented"; break;
					case 0x01: str="Extended Dynamic Allocation Capability for GPRS is implemented"; break;
					default: str="This should not happen";
				}
				proto_tree_add_text(tf_tree,
					tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
					"GPRS Extended Dynamic Allocation Capability: (%u) %s",oct>>(32-bits_needed),str);
				curr_bits_length -= bits_needed;
				oct <<= bits_needed;
				bits_in_oct -= bits_needed;
			}

			/*
			 * SMS/SM values
			 */
			bits_needed = 1;
			GET_DATA;

			/* analyse bits */
			if ((oct>>(32-bits_needed))==0)
			{
				proto_tree_add_text(tf_tree,
					tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
					"SMS/SM values: (%u) Bits are not available",oct>>(32-bits_needed));
				curr_bits_length -= bits_needed;
				oct <<= bits_needed;
   	 			bits_in_oct -= bits_needed;
			}
			else
			{
				curr_bits_length -= bits_needed;
				oct <<= bits_needed;
				bits_in_oct -= bits_needed;

				/*
				 * Switch-Measure-Switch value
				 */
				bits_needed = 4;
				GET_DATA;

				/* analyse bits */
				proto_tree_add_text(tf_tree,
					tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
					"Switch-Measure-Switch value: (%u) %d/4 timeslot (~%d microseconds)",
				oct>>(32-bits_needed),oct>>(32-bits_needed),(oct>>(32-bits_needed))*144);
				curr_bits_length -= bits_needed;
				oct <<= bits_needed;
				bits_in_oct -= bits_needed;

				/*
				 * Switch-Measure value
				 */
				bits_needed = 4;
				GET_DATA;

				/* analyse bits */
				proto_tree_add_text(tf_tree,
					tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
					"Switch-Measure value: (%u) %d/4 timeslot (~%d microseconds)",
				oct>>(32-bits_needed),oct>>(32-bits_needed),(oct>>(32-bits_needed))*144);
				curr_bits_length -= bits_needed;
				oct <<= bits_needed;
				bits_in_oct -= bits_needed;
			}

			/*
			 * ECSD multislot class?
			 */
			bits_needed = 1;
			GET_DATA;

			/* analyse bits */
			if ((oct>>(32-bits_needed))==0)
			{
				proto_tree_add_text(tf_tree,
					tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
					"ECSD multislot class: (%u) Bits are not available",oct>>(32-bits_needed));
				curr_bits_length -= bits_needed;
				oct <<= bits_needed;
				bits_in_oct -= bits_needed;
			}
			else
			{
				curr_bits_length -= bits_needed;
				oct <<= bits_needed;
				bits_in_oct -= bits_needed;

				/*
				 * ECSD multislot class
				 */
				bits_needed = 5;
				GET_DATA;

				/* analyse bits */
				proto_tree_add_text(tf_tree,
					tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
					"ECSD multislot class: (%u) %s",oct>>(32-bits_needed),multi_slot_str[oct>>(32-bits_needed)]);
				curr_bits_length -= bits_needed;
				oct <<= bits_needed;
				bits_in_oct -= bits_needed;
			}

			/*
			 * EGPRS multislot class?
			 */
			bits_needed = 1;
			GET_DATA;

			/* analyse bits */
			if ((oct>>(32-bits_needed))==0)
			{
				proto_tree_add_text(tf_tree,
					tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
					"EGPRS multislot class: (%u) Bits are not available",oct>>(32-bits_needed));
				curr_bits_length -= bits_needed;
				oct <<= bits_needed;
				bits_in_oct -= bits_needed;
			}
			else
			{
				curr_bits_length -= bits_needed;
				oct <<= bits_needed;
				bits_in_oct -= bits_needed;

				/*
				 * EGPRS multislot class
				 */
				bits_needed = 5;
				GET_DATA;

				/* analyse bits */
				proto_tree_add_text(tf_tree,
				tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
				"EGPRS multislot class: (%u) %s",oct>>(32-bits_needed),multi_slot_str[oct>>(32-bits_needed)]);
				curr_bits_length -= bits_needed;
				oct <<= bits_needed;
				bits_in_oct -= bits_needed;

				/*
				 * EGPRS Extended Dynamic Allocation Capability
				 */
				bits_needed = 1;
				GET_DATA;

				/* analyse bits */
				switch ( oct>>(32-bits_needed) )
				{
					case 0x00: str="Extended Dynamic Allocation Capability for EGPRS is not implemented"; break;
					case 0x01: str="Extended Dynamic Allocation Capability for EGPRS is implemented"; break;
					default: str="This should not happen";
				}
				proto_tree_add_text(tf_tree,
					tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
					"EGPRS Extended Dynamic Allocation Capability: (%u) %s",oct>>(32-bits_needed),str);
				curr_bits_length -= bits_needed;
				oct <<= bits_needed;
				bits_in_oct -= bits_needed;
			}

			/*
			 * DTM GPRS Multi Slot Class ?
			*/
			bits_needed = 1;
			GET_DATA;

			/* analyse bits */
			if ((oct>>(32-bits_needed))==0)
			{
				proto_tree_add_text(tf_tree,
					tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
					"DTM GPRS Multi Slot Class: (%u) Bits are not available",oct>>(32-bits_needed));
				curr_bits_length -= bits_needed;
				oct <<= bits_needed;
   	 			bits_in_oct -= bits_needed;
			}
			else
			{
				curr_bits_length -= bits_needed;
				oct <<= bits_needed;
   	 			bits_in_oct -= bits_needed;

				/*
				 * DTM GPRS Multi Slot Class
				 */
				bits_needed = 2;
				GET_DATA;

				/* analyse bits */
				dtm_gprs_mslot = oct>>(32-bits_needed);

				switch ( oct>>(32-bits_needed) )
				{
					case 0: str="Unused. If received, the network shall interpret this as Multislot class 5"; break;
					case 1: str="Multislot class 5 supported"; break;
					case 2: str="Multislot class 9 supported"; break;
					case 3: str="Multislot class 11 supported"; break;
					default: str="This should not happen";
				}
		
				proto_tree_add_text(tf_tree,
					tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
					"DTM GPRS Multi Slot Class: (%u) %s",oct>>(32-bits_needed),str);
				curr_bits_length -= bits_needed;
				oct <<= bits_needed;
				bits_in_oct -= bits_needed;

				/*
				 * Single Slot DTM
				 */
				bits_needed = 1;
				GET_DATA;

				/* analyse bits */
				switch ( oct>>(32-bits_needed) )
				{
					case 0x00: str="Single Slot DTM not supported"; break;
					case 0x01: str="Single Slot DTM supported"; break;
					default: str="This should not happen";
				}
				proto_tree_add_text(tf_tree,
					tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
					"Single Slot DTM: (%u) %s",oct>>(32-bits_needed),str);
				curr_bits_length -= bits_needed;
				oct <<= bits_needed;
				bits_in_oct -= bits_needed;

				/*
				 * DTM EGPRS Multi Slot Class ?
				*/
				bits_needed = 1;
				GET_DATA;

				/* analyse bits */
				dtm_egprs_mslot = oct>>(32-bits_needed);

				if ((oct>>(32-bits_needed))==0)
				{
					proto_tree_add_text(tf_tree,
						tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
						"DTM EGPRS Multi Slot Class: (%u) Bits are not available",oct>>(32-bits_needed));
					curr_bits_length -= bits_needed;
					oct <<= bits_needed;
   	 				bits_in_oct -= bits_needed;
				}
				else
				{
					curr_bits_length -= bits_needed;
					oct <<= bits_needed;
  	 	 			bits_in_oct -= bits_needed;

					/*
					 * DTM EGPRS Multi Slot Class
					 */
					bits_needed = 2;
					GET_DATA;

					/* analyse bits */
					switch ( oct>>(32-bits_needed) )
					{
						case 0: str="Unused. If received, the network shall interpret this as Multislot class 5"; break;
						case 1: str="Multislot class 5 supported"; break;
						case 2: str="Multislot class 9 supported"; break;
						case 3: str="Multislot class 11 supported"; break;
						default: str="This should not happen";
					}

					proto_tree_add_text(tf_tree,
						tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
						"DTM EGPRS Multi Slot Class: (%u) %s",oct>>(32-bits_needed),str);
					curr_bits_length -= bits_needed;
					oct <<= bits_needed;
					bits_in_oct -= bits_needed;
				}
			}
		}

		/*
		 * 8PSK Power Capability?
		 */
		bits_needed = 1;
		GET_DATA;

		/* analyse bits */
		if ((oct>>(32-bits_needed))==0)
		{
			proto_tree_add_text(tf_tree,
				tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
				"8PSK Power Capability: (%u) Bits are not available",oct>>(32-bits_needed));
			curr_bits_length -= bits_needed;
			oct <<= bits_needed;
			bits_in_oct -= bits_needed;
		}
		else
		{
			curr_bits_length -= bits_needed;
			oct <<= bits_needed;
			bits_in_oct -= bits_needed;

			/*
			 * 8PSK Power Capability
			 */
			bits_needed = 2;
			GET_DATA;

			/* analyse bits */
			switch ( oct>>(32-bits_needed) )
			{
				case 0x00: str="Reserved"; break;
				case 0x01: str="Power class E1"; break;
				case 0x02: str="Power class E2"; break;
				case 0x03: str="Power class E3"; break;
				default: str="This should not happen";
			}

			proto_tree_add_text(tf_tree,
				tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
				"8PSK Power Capability: (%u) %s",oct>>(32-bits_needed),str);
			curr_bits_length -= bits_needed;
			oct <<= bits_needed;
			bits_in_oct -= bits_needed;
		}

		/*
		 * COMPACT Interference Measurement Capability
		 */
		bits_needed = 1;
		GET_DATA;

		/* analyse bits */
		switch ( oct>>(32-bits_needed) )
		{
			case 0x00: str="COMPACT Interference Measurement Capability is not implemented"; break;
			case 0x01: str="COMPACT Interference Measurement Capability is implemented"; break;
			default: str="This should not happen";
		}

		proto_tree_add_text(tf_tree,
			tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
			"COMPACT Interference Measurement Capability: (%u) %s",oct>>(32-bits_needed),str);
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;

		/*
		 * Revision Level Indicator
		 */
		bits_needed = 1;
		GET_DATA;

		/* analyse bits */
		switch ( oct>>(32-bits_needed) )
		{
			case 0x00: str="The ME is Release 98 or older"; break;
			case 0x01: str="The ME is Release 99 onwards"; break;
			default: str="This should not happen";
		}

		proto_tree_add_text(tf_tree,
			tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
			"Revision Level Indicator: (%u) %s",oct>>(32-bits_needed),str);
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;

		/*
		 * UMTS FDD Radio Access Technology Capability
		 */
		bits_needed = 1;
		GET_DATA;

		/* analyse bits */
		switch ( oct>>(32-bits_needed) )
		{
			case 0x00: str="UMTS FDD not supported"; break;
			case 0x01: str="UMTS FDD supported"; break;
			default: str="This should not happen";
		}

		proto_tree_add_text(tf_tree,
			tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
			"UMTS FDD Radio Access Technology Capability: (%u) %s",oct>>(32-bits_needed),str);
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;

		/*
		 * UMTS 3.84 Mcps TDD Radio Access Technology Capability
		 */
		bits_needed = 1;
		GET_DATA;

	/* analyse bits */
		switch ( oct>>(32-bits_needed) )
		{
			case 0x00: str="UMTS 3.84 Mcps TDD not supported"; break;
			case 0x01: str="UMTS 3.84 Mcps TDD supported"; break;
			default: str="This should not happen";
		}

		proto_tree_add_text(tf_tree,
			tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
			"UMTS 3.84 Mcps TDD Radio Access Technology Capability: (%u) %s",oct>>(32-bits_needed),str);
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;

		/*
		 * CDMA 2000 Radio Access Technology Capability
		 */
		bits_needed = 1;
		GET_DATA;

		/* analyse bits */
		switch ( oct>>(32-bits_needed) )
		{
			case 0x00: str="CDMA 2000 not supported"; break;
			case 0x01: str="CDMA 2000 supported"; break;
			default: str="This should not happen";
		}

		proto_tree_add_text(tf_tree,
			tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
			"CDMA 2000 Radio Access Technology Capability: (%u) %s",oct>>(32-bits_needed),str);
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;

		/*
		 * UMTS 1.28 Mcps TDD Radio Access Technology Capability
		 */
		bits_needed = 1;
		GET_DATA;

		/* analyse bits */
		switch ( oct>>(32-bits_needed) )
		{
			case 0x00: str="UMTS 1.28 Mcps TDD not supported"; break;
			case 0x01: str="UMTS 1.28 Mcps TDD supported"; break;
			default: str="This should not happen";
		}

		proto_tree_add_text(tf_tree,
			tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
			"UMTS 1.28 Mcps TDD Radio Access Technology Capability: (%u) %s",oct>>(32-bits_needed),str);
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;

		/*
		 * GERAN Feature Package 1
		 */
		bits_needed = 1;
		GET_DATA;

		/* analyse bits */
		switch ( oct>>(32-bits_needed) )
		{
			case 0x00: str="GERAN feature package 1 not supported"; break;
			case 0x01: str="GERAN feature package 1 supported"; break;
			default: str="This should not happen";
		}

		proto_tree_add_text(tf_tree,
		tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
		"GERAN Feature Package 1: (%u) %s",oct>>(32-bits_needed),str);
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;

		/*
		 * Extended DTM (E)GPRS Multi Slot Class
		 */
		bits_needed = 1;
		GET_DATA;

		/* analyse bits */
		if ((oct>>(32-bits_needed))==0)
		{
			proto_tree_add_text(tf_tree,
				tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
				"Extended DTM (E)GPRS Multi Slot Class: (%u) Bits are not available",oct>>(32-bits_needed));
			curr_bits_length -= bits_needed;
			oct <<= bits_needed;
			bits_in_oct -= bits_needed;
		}
		else
		{
			curr_bits_length -= bits_needed;
			oct <<= bits_needed;
			bits_in_oct -= bits_needed;

			/*
			 * Extended DTM GPRS Multi Slot Class
			 */
			bits_needed = 2;
			GET_DATA;

			/* analyse bits */
			switch ( (oct>>(32-bits_needed))|(dtm_gprs_mslot<<4) )
			{
				case 0x00: str="Unused. If received, it shall be interpreted as Multislot class 5 supported"; break;
				case 0x01: str="Unused. If received, it shall be interpreted as Multislot class 5 supported"; break;
				case 0x02: str="Unused. If received, it shall be interpreted as Multislot class 5 supported"; break;
				case 0x03: str="Unused. If received, it shall be interpreted as Multislot class 5 supported"; break;
				case 0x10: str="Multislot class 5 supported"; break;
				case 0x11: str="Multislot class 6 supported"; break;
				case 0x12: str="Unused. If received, it shall be interpreted as Multislot class 5 supported"; break;
				case 0x13: str="Unused. If received, it shall be interpreted as Multislot class 5 supported"; break;
				case 0x20: str="Multislot class 9 supported"; break;
				case 0x21: str="Multislot class 10 supported"; break;
				case 0x22: str="Unused. If received, it shall be interpreted as Multislot class 9 supported"; break;
				case 0x23: str="Unused. If received, it shall be interpreted as Multislot class 9 supported"; break;
				case 0x30: str="Multislot class 11 supported"; break;
				case 0x31: str="Unused. If received, it shall be interpreted as Multislot class 11 supported"; break;
				case 0x32: str="Unused. If received, it shall be interpreted as Multislot class 11 supported"; break;
				case 0x33: str="Unused. If received, it shall be interpreted as Multislot class 11 supported"; break;
				default: str="This should not happen";
			}

			proto_tree_add_text(tf_tree,
				tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
				"Extended DTM GPRS Multi Slot Class: (%u) %s",oct>>(32-bits_needed),str);
			curr_bits_length -= bits_needed;
			oct <<= bits_needed;
			bits_in_oct -= bits_needed;

			if ( dtm_egprs_mslot <= 3 )
			{
				/*
				 * Extended DTM EGPRS Multi Slot Class
				 */
				bits_needed = 2;
				GET_DATA;

				/* analyse bits */
				switch ( (oct>>(32-bits_needed))|(dtm_egprs_mslot<<4) )
				{
					case 0x00: str="Unused. If received, it shall be interpreted as Multislot class 5 supported"; break;
					case 0x01: str="Unused. If received, it shall be interpreted as Multislot class 5 supported"; break;
					case 0x02: str="Unused. If received, it shall be interpreted as Multislot class 5 supported"; break;
					case 0x03: str="Unused. If received, it shall be interpreted as Multislot class 5 supported"; break;
					case 0x10: str="Multislot class 5 supported"; break;
					case 0x11: str="Multislot class 6 supported"; break;
					case 0x12: str="Unused. If received, it shall be interpreted as Multislot class 5 supported"; break;
					case 0x13: str="Unused. If received, it shall be interpreted as Multislot class 5 supported"; break;
					case 0x20: str="Multislot class 9 supported"; break;
					case 0x21: str="Multislot class 10 supported"; break;
					case 0x22: str="Unused. If received, it shall be interpreted as Multislot class 9 supported"; break;
					case 0x23: str="Unused. If received, it shall be interpreted as Multislot class 9 supported"; break;
					case 0x30: str="Multislot class 11 supported"; break;
					case 0x31: str="Unused. If received, it shall be interpreted as Multislot class 11 supported"; break;
					case 0x32: str="Unused. If received, it shall be interpreted as Multislot class 11 supported"; break;
					case 0x33: str="Unused. If received, it shall be interpreted as Multislot class 11 supported"; break;
					default: str="This should not happen";
				}

				proto_tree_add_text(tf_tree,
					tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
					"Extended DTM EGPRS Multi Slot Class: (%u) %s",oct>>(32-bits_needed),str);
				curr_bits_length -= bits_needed;
				oct <<= bits_needed;
				bits_in_oct -= bits_needed;
			}
		}

		/*
		 * Modulation based multislot class support
		 */
		bits_needed = 1;
		GET_DATA;

		/* analyse bits */
		switch ( oct>>(32-bits_needed) )
		{
			case 0x00: str="Modulation based multislot class not supported"; break;
			case 0x01: str="Modulation based multislot class supported"; break;
			default: str="This should not happen";
		}

		proto_tree_add_text(tf_tree,
			tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
			"Modulation based multislot class support: (%u) %s",oct>>(32-bits_needed),str);
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;

		/*
		 * High Multislot Capability
		 */
		bits_needed = 1;
		GET_DATA;

		/* analyse bits */
		if ((oct>>(32-bits_needed))==0)
		{
			proto_tree_add_text(tf_tree,
				tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
				"High Multislot Capability: (%u) Bits are not available",oct>>(32-bits_needed));
			curr_bits_length -= bits_needed;
			oct <<= bits_needed;
			bits_in_oct -= bits_needed;
		}
		else
		{
			curr_bits_length -= bits_needed;
			oct <<= bits_needed;
			bits_in_oct -= bits_needed;

			/*
			 * High Multislot Capability
			 */
			bits_needed = 2;
			GET_DATA;

			/* analyse bits */
			proto_tree_add_text(tf_tree,
			tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
			"High Multislot Capability: 0x%02x (%u) - This field effect all other multislot fields. To understand the value please read TS 24.008 5.6.0 Release 5 Chap 10.5.5.12 Page 406",oct>>(32-bits_needed),oct>>(32-bits_needed));
			curr_bits_length -= bits_needed;
			oct <<= bits_needed;
			bits_in_oct -= bits_needed;
		}

		/*
		 * GERAN Iu Mode Capability
		 */
		bits_needed = 1;
		GET_DATA;

		/* analyse bits */
		switch ( oct>>(32-bits_needed) )
		{
			case 0x00: str="GERAN Iu mode not supported"; break;
			case 0x01: str="GERAN Iu mode supported"; break;
			default: str="This should not happen";
		}

		proto_tree_add_text(tf_tree,
			tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
			"GERAN Iu Mode Capability: (%u) %s",oct>>(32-bits_needed),str);
		curr_bits_length -= bits_needed;
		oct <<= bits_needed;
		bits_in_oct -= bits_needed;

		/*
		 * GMSK/8-PSK Multislot Power Profile
		 */
		bits_needed = 1;
		GET_DATA;

		/* analyse bits */
		if ((oct>>(32-bits_needed))==0)
		{
			proto_tree_add_text(tf_tree,
				tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
				"GMSK/8-PSK Multislot Power Profile: (%u) Bits are not available",oct>>(32-bits_needed));
			curr_bits_length -= bits_needed;
			oct <<= bits_needed;
   		 	bits_in_oct -= bits_needed;
		}
		else
		{
			curr_bits_length -= bits_needed;
			oct <<= bits_needed;
			bits_in_oct -= bits_needed;

			/*
			 * GMSK Multislot Power Profile
			 */
			bits_needed = 2;
			GET_DATA;

			/* analyse bits */
			switch ( oct>>(32-bits_needed) )
			{
				case 0x00: str="GMSK_MULTISLOT_POWER_PROFILE 0"; break;
				case 0x01: str="GMSK_MULTISLOT_POWER_PROFILE 1"; break;
				case 0x02: str="GMSK_MULTISLOT_POWER_PROFILE 2"; break;
				case 0x03: str="GMSK_MULTISLOT_POWER_PROFILE 3"; break;
				default: str="This should not happen";
			}
	
			proto_tree_add_text(tf_tree,
				tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
				"GMSK Multislot Power Profile: (%u) %s",oct>>(32-bits_needed),str);
			curr_bits_length -= bits_needed;
			oct <<= bits_needed;
			bits_in_oct -= bits_needed;

			/*
			 * 8-PSK Multislot Power Profile
			 */
			bits_needed = 2;
			GET_DATA;

			/* analyse bits */
			switch ( oct>>(32-bits_needed) )
			{
				case 0x00: str="8-PSK_MULTISLOT_POWER_PROFILE 0"; break;
				case 0x01: str="8-PSK_MULTISLOT_POWER_PROFILE 1"; break;
				case 0x02: str="8-PSK_MULTISLOT_POWER_PROFILE 2"; break;
				case 0x03: str="8-PSK_MULTISLOT_POWER_PROFILE 3"; break;
				default: str="This should not happen";
			}
	
			proto_tree_add_text(tf_tree,
			tvb, curr_offset-1-add_ocetets, 1+add_ocetets,
			"8-PSK Multislot Power Profile: (%u) %s",oct>>(32-bits_needed),str);
			curr_bits_length -= bits_needed;
			oct <<= bits_needed;
			bits_in_oct -= bits_needed;

		}

		/*
		 * we are too long ... so jump over it
		 */
		while ( curr_bits_length > 0 )
		{
			if ( curr_bits_length > 8 )
				bits_needed = 8;
			else
				bits_needed = curr_bits_length;
			GET_DATA;
			curr_bits_length -= bits_needed;
			oct <<= bits_needed;
			bits_in_oct -= bits_needed;
		}

	} while ( 1 );

	curr_offset+= curr_len;
	   
	EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

	return(curr_offset - offset);
}

/*
 * [7] 10.5.5.14
 */
static guint16
de_gmm_cause(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint8	oct;
	guint32	curr_offset;
	const gchar	*str;

	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	switch ( oct )
	{
		/* additional causes can be found in annex g */
		case 0x02: str="IMSI unknown in HLR"; break;
		case 0x03: str="Illegal MS"; break;
		case 0x04: str="IMSI unknown in VLR"; break;
		case 0x05: str="IMEI not accepted"; break;
		case 0x06: str="Illegal ME"; break;
		case 0x07: str="GPRS services not allowed"; break;
		case 0x08: str="GPRS services and non-GPRS services not	allowed"; break;
		case 0x09: str="MS identity cannot be derived by the network"; break;
		case 0x0a: str="Implicitly detached"; break;
		case 0x0b: str="PLMN not allowed"; break;
		case 0x0c: str="Location Area not allowed"; break;
		case 0x0d: str="Roaming not allowed in this location area"; break;
		case 0x0e: str="GPRS services not allowed in this PLMN"; break;
		case 0x0f: str="No Suitable Cells In Location Area"; break;
		case 0x10: str="MSC temporarily not reachable"; break;
		case 0x11: str="Network failure"; break;
		case 0x14: str="MAC failure"; break;
		case 0x15: str="Synch failure"; break;
		case 0x16: str="Congestion"; break;
		case 0x17: str="GSM authentication unacceptable"; break;
		case 0x20: str="Service option not supported"; break;
		case 0x21: str="Requested service option not subscribed"; break;
		case 0x22: str="Service option temporarily out of order"; break;
		case 0x26: str="Call cannot be identified"; break;
		case 0x28: str="No PDP context activated"; break;
		case 0x30: str="retry upon entry into a new cell"; break;
		case 0x31: str="retry upon entry into a new cell"; break;
		case 0x32: str="retry upon entry into a new cell"; break;
		case 0x33: str="retry upon entry into a new cell"; break;
		case 0x34: str="retry upon entry into a new cell"; break;
		case 0x35: str="retry upon entry into a new cell"; break;
		case 0x36: str="retry upon entry into a new cell"; break;
		case 0x37: str="retry upon entry into a new cell"; break;
		case 0x38: str="retry upon entry into a new cell"; break;
		case 0x39: str="retry upon entry into a new cell"; break;
		case 0x3a: str="retry upon entry into a new cell"; break;
		case 0x3b: str="retry upon entry into a new cell"; break;
		case 0x3c: str="retry upon entry into a new cell"; break;
		case 0x3d: str="retry upon entry into a new cell"; break;
		case 0x3e: str="retry upon entry into a new cell"; break;
		case 0x3f: str="retry upon entry into a new cell"; break;
		case 0x5f: str="Semantically incorrect message"; break;
		case 0x60: str="Invalid mandatory information"; break;
		case 0x61: str="Message type non-existent or not implemented"; break;
		case 0x62: str="Message type not compatible with the protocol state"; break;
		case 0x63: str="Information element non-existent or not implemented"; break;
		case 0x64: str="Conditional IE error"; break;
		case 0x65: str="Message not compatible with the protocol state"; break;
		case 0x6f: str="Protocol error, unspecified"; break;
		default: str="Protocol error, unspecified";
	}

	proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"gmm Cause: (%u) %s",
		oct,
		str);

	curr_offset++;

	/* no length check possible */

	return(curr_offset - offset);
}

/*
 * [7] 10.5.5.15 Routing area identification
 */
guint16
de_gmm_rai(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	proto_tree	*subtree;
	proto_item	*item;
	guint32	mcc;
	guint32	mnc;
	guint32	lac;
	guint32	rac;
	guint32	curr_offset;

	curr_offset = offset;

	mcc = (tvb_get_guint8(tvb, curr_offset) & 0x0f) <<8;
	mcc |= (tvb_get_guint8(tvb, curr_offset) & 0xf0);
	mcc |= (tvb_get_guint8(tvb, curr_offset+1) & 0x0f);
	mnc = (tvb_get_guint8(tvb, curr_offset+2) & 0x0f) <<8;
	mnc |= (tvb_get_guint8(tvb, curr_offset+2) & 0xf0);
	mnc |= (tvb_get_guint8(tvb, curr_offset+1) & 0xf0) >>4;
	if ((mnc&0x000f) == 0x000f)
		 mnc = mnc>>4;

	lac = tvb_get_guint8(tvb, curr_offset+3);
	lac <<= 8;
	lac |= tvb_get_guint8(tvb, curr_offset+4);
	rac = tvb_get_guint8(tvb, curr_offset+5);

	item = proto_tree_add_text(tree,
		tvb, curr_offset, 6,
		"Routing area identification: %x-%x-%x-%x",
		mcc,mnc,lac,rac);

	subtree = proto_item_add_subtree(item, ett_gmm_rai);
	dissect_e212_mcc_mnc(tvb, subtree, offset);
	curr_offset+=6;

	/* no length check possible */

	return(curr_offset - offset);
}

/*
 * [7] 10.5.5.17
 */
static guint16
de_gmm_update_res(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint8	oct;
	guint32	curr_offset;
	const gchar	*str;

	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	/* IMPORTANT - IT'S ASSUMED THAT THE INFORMATION IS IN THE HIGHER NIBBLE */
	oct >>= 4;

	switch(oct&7)
	{
		case 0: str="RA updated"; break;
		case 1: str="combined RA/LA updated";	break;
		default: str="reserved";
	}

	proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"Update Result: (%u) %s",
		oct&7,
		str);

	curr_offset++;

	/* no length check possible */

	return(curr_offset - offset);
}

/*
 * [7] 10.5.5.18
 */
static guint16
de_gmm_update_type(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint8	oct;
	guint8	oct_ciph;
	guint32	curr_offset;
	const gchar	*str_follow;
	const gchar	*str_update;
	proto_item  *tf = NULL;
	proto_tree	  *tf_tree = NULL;

	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);
	oct_ciph = oct>>4;

	oct &= 0x0f;

	switch(oct&7)
	{
		case 0: str_update="RA updating"; break;
		case 1: str_update="combined RA/LA updating"; break;
		case 2: str_update="combined RA/LA updating with IMSI attach"; break;
		case 3: str_update="Periodic updating"; break;
		default: str_update="reserved";
	}
	switch(oct&8)
	{
		case 8: str_follow="Follow-on request pending"; break;
		default: str_follow="No follow-on request pending";
	}

	tf = proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"Update Type");

	tf_tree = proto_item_add_subtree(tf, ett_gmm_update_type );

	proto_tree_add_text(tf_tree,
		tvb, curr_offset, 1,
		"Type: (%u) %s",
		oct&7,
		str_update);
	proto_tree_add_text(tf_tree,
		tvb, curr_offset, 1,
		"Follow: (%u) %s",
		(oct>>3)&1,
		str_follow);

	/* The ciphering key sequence number is added here */
	proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"Ciphering key sequence number: 0x%02x (%u)",
		oct_ciph,
		oct_ciph);

	curr_offset++;

	/* no length check possible */

	return(curr_offset - offset);
}

/*
 * [7] 10.5.5.19
 */
static guint16
de_gmm_ac_ref_nr(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint8	oct;
	guint32	curr_offset;

	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"A&C reference number: 0x%02x (%u)",
		oct&0xf,
		oct&0xf);

	curr_offset++;

	/* no length check possible */

	return(curr_offset - offset);
}

/*
 * [7] 10.5.5.19
 */
static guint16
de_gmm_ac_ref_nr_h(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint8	oct;
	guint32	curr_offset;

	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	/* IMPORTANT - IT'S ASSUMED THAT THE INFORMATION IS IN THE HIGHER NIBBLE */
	oct >>= 4;

	proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"A&C reference number: 0x%02x (%u)",
		oct,
		oct);

	curr_offset++;

	/* no length check possible */

	return(curr_offset - offset);
}

/*
 * [8] 10.5.5.20
 */
static guint16
de_gmm_service_type(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint8	oct;
	guint8	oct_ciph;
	guint32	curr_offset;
	const gchar *str;

	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);
	oct_ciph = oct;
	oct_ciph &= 7;

	oct = oct >> 4;

	switch ( oct&7 )
	{
		case 0: str="Signalling"; break;
		case 1: str="Data"; break;
		case 2: str="Paging Response"; break;
		case 3: str="MBMS Notification Response"; break;/* reponse->response*/
		default: str="reserved";
	}

	/* The ciphering key sequence number is added here */
	proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"Ciphering key sequence number: 0x%02x (%u)",
		oct_ciph,
		oct_ciph);

	proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"Service Type: (%u) %s",
		oct&7,
		str);

	curr_offset++;

	/* no length check possible */

	return(curr_offset - offset);
}

/*
 * [7] 10.5.5.21
 */
static guint16
de_gmm_cell_notfi(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	proto_tree_add_text(tree,
		tvb, curr_offset, 0,
		"Cell Notification");

	/* no length check possible */

	return(curr_offset - offset);
}

/*
 * [7] 10.5.5.22
 */
static guint16
de_gmm_ps_lcs_cap(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint8	oct;
	guint32	curr_offset;

	gchar	str_otd[2][40]={ "MS assisted E-OTD not supported",
				"MS assisted E-OTD supported" };
	gchar	str_gps[2][40]={ "MS assisted GPS not supported",
				"MS assisted GPS supported" };

	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	oct <<=3;   /* move away the spare bits */

	proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"OTD-A: (%u) %s",
		oct>>7,
		str_otd[oct>>7]);
		oct <<=1;
	proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"OTD-B: (%u) %s",
		oct>>7,
		str_otd[oct>>7]);
		oct <<=1;

	proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"GPS-A: (%u) %s",
		oct>>7,
		str_gps[oct>>7]);
		oct <<=1;
	proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"GPS-B: (%u) %s",
		oct>>7,
		str_gps[oct>>7]);
		oct <<=1;
	proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"GPS-C: (%u) %s",
		oct>>7,
		str_gps[oct>>7]);

	curr_offset++;

	EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

	return(curr_offset - offset);
}

/*
 * [7] 10.5.5.23
 */
static guint16
de_gmm_net_feat_supp(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint8	oct;
	guint32	curr_offset;
	const gchar	*str;

	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	switch(oct&8)
	{
		case 8: str="LCS-MOLR via PS domain not supported"; break;
		default: str="LCS-MOLR via PS domain supported";
	}

	proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"Network Feature Support: (%u) %s",
		(oct>>3)&1,
		str);

	curr_offset++;

	/* no length check possible */

	return(curr_offset - offset);
}

/* [7] 10.5.5.24 Inter RAT information container */
static guint16
de_gmm_rat_info_container(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;
	tvbuff_t *rrc_irat_ho_info_tvb;
	static packet_info p_info;

	curr_offset = offset;

/* The value part of the Inter RAT information container information element is the INTER RAT HANDOVER INFO as
defined in 3GPP TS 25.331 [23c]. If this field includes padding bits, they are defined in 3GPP TS 25.331 [23c].*/
	rrc_irat_ho_info_tvb = tvb_new_subset(tvb, curr_offset, len, len);
	if (rrc_irat_ho_info_handle)
		call_dissector(rrc_irat_ho_info_handle, rrc_irat_ho_info_tvb, &p_info , tree);
	else
		proto_tree_add_text(tree, tvb, curr_offset, len,"INTER RAT HANDOVER INFO - Not decoded");

	return len;

}

/*
 * [7] 10.5.7.1
 */
static guint16
de_gc_context_stat(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint8	oct;
	guint16	pdp_nr;
	guint32	curr_offset;
	proto_item  *tf = NULL;
	proto_tree  *tf_tree = NULL;

	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	tf = proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"PDP Context Status");

	tf_tree = proto_item_add_subtree(tf, ett_gmm_context_stat );

	oct = tvb_get_guint8(tvb, curr_offset);

	for ( pdp_nr=0;pdp_nr<16; pdp_nr++ )
	{
		if ( pdp_nr == 8 )
		{
			curr_offset++;
			oct = tvb_get_guint8(tvb, curr_offset);
		}
		proto_tree_add_text(tf_tree,
			tvb, curr_offset, 1,
			"NSAPI %d: (%u) %s",pdp_nr,
			oct&1,
			pdp_str[oct&1]);
		oct>>=1;
	}

	curr_offset++;

	EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

	return(curr_offset - offset);
}

/*
 * [7] 10.5.7.2
 */
static guint16
de_gc_radio_prio(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint8	oct;
	guint32	curr_offset;
	const gchar	*str;

	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	switch ( oct&7 )
	{
		case 1: str="priority level 1 (highest)"; break;
		case 2: str="priority level 2"; break;
		case 3: str="priority level 3"; break;
		case 4: str="priority level 4 (lowest)"; break;
		default: str="priority level 4 (lowest)";
	}

	proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"Radio Priority (PDP or SMS): (%u) %s",
		oct&7,
		str);

	curr_offset++;

	return(curr_offset - offset);
}

/*
 * [7] 10.5.7.3
 */
static guint16
de_gc_timer(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint8	oct;
	guint16	val;
	guint32	curr_offset;
	const gchar	*str;

	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	val = oct&0x1f;

	switch(oct>>5)
	{
		case 0: str="sec"; val*=2; break;
		case 1: str="min"; break;
		case 2: str="min"; val*=6; break;
		case 7:
			proto_tree_add_text(tree,
				tvb, curr_offset, 1,
				"GPRS Timer: timer is deactivated");

		default: str="min";
	}

	proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"GPRS Timer: (%u) %u %s",
		oct, val,
		str);

	curr_offset++;

	/* no length check possible */

	return(curr_offset - offset);
}

/*
 * [7] 10.5.7.4
 */
static guint16
de_gc_timer2(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string, int string_len _U_)
{
	guint8	oct;
	guint16	val;
	guint32	curr_offset;
	const gchar	*str;

	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	val = oct&0x1f;

	switch(oct>>5)
	{
		case 0: str="sec"; val*=2; break;
		case 1: str="min"; break;
		case 2: str="min"; val*=6; break;
		case 7:
			proto_tree_add_text(tree,
			tvb, curr_offset, 1,
			"GPRS Timer: timer is deactivated");

		default: str="min";
	}

	proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"GPRS Timer: (%u) %u %s %s",
		oct, val,
		str, add_string ? add_string : "");

	curr_offset++;

	return(curr_offset - offset);
}

/*
 * [7] 10.5.7.5
 */
static guint16
de_gc_radio_prio2(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint8	oct;
	guint32	curr_offset;
	const gchar	*str;

	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	/* IMPORTANT - IT'S ASSUMED THAT THE INFORMATION IS IN THE HIGHER NIBBLE */
	oct >>= 4;

	switch ( oct&7 )
	{
		case 1: str="priority level 1 (highest)"; break;
		case 2: str="priority level 2"; break;
		case 3: str="priority level 3"; break;
		case 4: str="priority level 4 (lowest)"; break;
		default: str="priority level 4 (lowest)";
	}

	proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"Radio Priority (TOM8): (%u) %s",
		oct&7,
		str);

	curr_offset++;

	return(curr_offset - offset);
}

/*
 * [8] 10.5.7.6 MBMS context status
 */
static guint16
de_gc_mbms_context_stat(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;
	guint8	oct, i, j;
	proto_item  *tf = NULL;
	proto_tree  *tf_tree = NULL;

	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	tf = proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"MBMS Context Status");

	tf_tree = proto_item_add_subtree(tf, ett_gmm_context_stat );

	for (i=0; i<len; i++)
	{
		oct = tvb_get_guint8(tvb, curr_offset);

		for (j=0; j<8; j++)
		{
			proto_tree_add_text(tf_tree,
				tvb, curr_offset, 1,
				"NSAPI %d: (%u) %s",128+i*8+j,
				oct&1,
				pdp_str[oct&1]);
			oct>>=1;
		}
		curr_offset++;
	}

	return(len);
}
/*
 * [7] 10.5.6.1
 */
#define MAX_APN_LENGTH		50

guint16
de_sm_apn(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len _U_)
{
	guint32	curr_offset;
	guint	curr_len;
	const guint8	*cptr;
	guint8	  str[MAX_APN_LENGTH+1];

	cptr = tvb_get_ptr(tvb, offset, len);

	curr_offset = offset;

	/* init buffer and copy it */
	memset ( str , 0 , MAX_APN_LENGTH );
	memcpy ( str , cptr , len<MAX_APN_LENGTH?len:MAX_APN_LENGTH );

	curr_len = 0;
	while (( curr_len < len ) && ( curr_len < MAX_APN_LENGTH ))
	{
		guint step = str[curr_len];
		str[curr_len]='.';
		curr_len += step+1;
	}

	proto_tree_add_text(tree,
		tvb, curr_offset, len,
		"APN: %s %s", str+1 , add_string ? add_string : "");

	curr_offset+= len;

	EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

	return(curr_offset - offset);
}

/*
 * [7] 10.5.6.2
 */
static guint16
de_sm_nsapi(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string, int string_len _U_)
{
	guint8	oct;
	guint32	curr_offset;

	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"NSAPI: 0x%02x (%u) %s",
		oct&0x0f, oct&0x0f,add_string ? add_string : "");

	curr_offset++;

	return(curr_offset - offset);
}

/*
 * [7] 10.5.6.3
 */
static guint16
de_sm_pco(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;
	guint	curr_len;
	guchar	oct;
	struct e_in6_addr ipv6_addr;

	curr_len = len;
	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);
	curr_len--;
	curr_offset++;

	proto_tree_add_text(tree,tvb, curr_offset, 1, "Ext: 0x%02x (%u)",oct>>7,oct>>7);
	proto_tree_add_text(tree,tvb, curr_offset, 1, "Configuration Protocol: PPP (%u)",oct&0x0f);

	while ( curr_len > 0 )
	{
		guchar e_len;
		guint16 prot;
		tvbuff_t *l3_tvb;
		dissector_handle_t handle = NULL;
		static packet_info p_info;

		prot = tvb_get_guint8(tvb, curr_offset);
		prot <<= 8;
		prot |= tvb_get_guint8(tvb, curr_offset+1);
		e_len = tvb_get_guint8(tvb, curr_offset+2);
		curr_len-=3;
		curr_offset+=3;

		switch ( prot )
		{
			case 0x0001:
			{
				proto_tree_add_text(tree,tvb, curr_offset-3, 2, "Parameter: (%u) P-CSCF Address" , prot );
				proto_tree_add_text(tree,tvb, curr_offset-1, 1, "Length: 0x%02x (%u)", e_len , e_len);

				tvb_get_ipv6(tvb, curr_offset, &ipv6_addr);
				proto_tree_add_text(tree,
				tvb, curr_offset, 16,
				"IPv6: %s", ip6_to_str(&ipv6_addr));
				break;
			}
			case 0x0002:
				proto_tree_add_text(tree,tvb, curr_offset-3, 2, "Parameter: (%u) IM CN Subsystem Signaling Flag" , prot );
				proto_tree_add_text(tree,tvb, curr_offset-1, 1, "Length: 0x%02x (%u)", e_len , e_len);
				break;
			case 0x0003:
			{
				proto_tree_add_text(tree,tvb, curr_offset-3, 2, "Parameter: (%u) DNS Server Address" , prot );
				proto_tree_add_text(tree,tvb, curr_offset-1, 1, "Length: 0x%02x (%u)", e_len , e_len);

				tvb_get_ipv6(tvb, curr_offset, &ipv6_addr);
				proto_tree_add_text(tree,
				tvb, curr_offset, 16,
				"IPv6: %s", ip6_to_str(&ipv6_addr));
				break;
			}
			case 0x0004:
				proto_tree_add_text(tree,tvb, curr_offset-3, 2, "Parameter: (%u) Policy Control rejection code" , prot );
				proto_tree_add_text(tree,tvb, curr_offset-1, 1, "Length: 0x%02x (%u)", e_len , e_len);
				oct = tvb_get_guint8(tvb, curr_offset);
				proto_tree_add_text(tree,tvb, curr_offset, 1, "Reject Code: 0x%02x (%u)", e_len , e_len);
				break;
			default:
			{
				handle = dissector_get_port_handle ( gprs_sm_pco_subdissector_table , prot );
				if ( handle != NULL )
				{
					proto_tree_add_text(tree,tvb, curr_offset-3, 2, "Protocol: (%u) %s" ,
					prot , val_to_str(prot, ppp_vals, "Unknown"));
					proto_tree_add_text(tree,tvb, curr_offset-1, 1, "Length: 0x%02x (%u)", e_len , e_len);
					/*
					 * dissect the embedded message
					 */
					l3_tvb = tvb_new_subset(tvb, curr_offset, e_len, e_len);
					call_dissector(handle, l3_tvb ,  &p_info  , tree );
				}
				else
				{
					proto_tree_add_text(tree,tvb, curr_offset-3, 2, "Protocol/Parameter: (%u) unknown" , prot );
					proto_tree_add_text(tree,tvb, curr_offset-1, 1, "Length: 0x%02x (%u)", e_len , e_len);
					/*
					* dissect the embedded DATA message
					*/
					l3_tvb = tvb_new_subset(tvb, curr_offset, e_len, e_len);
					call_dissector(data_handle, l3_tvb, &p_info , tree);
				}
			}
		}

		curr_len-= e_len;
		curr_offset+= e_len;
	}
	curr_offset+= curr_len;

	EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

	return(curr_offset - offset);
}

/*
 * [7] 10.5.6.4
 */
static guint16
de_sm_pdp_addr(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;
	guint	curr_len;
	const gchar	*str;
	guchar	  oct;
	guchar	  oct2;
	struct e_in6_addr ipv6_addr;

	curr_len = len;
	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	switch ( oct&0x0f )
	{
		case 0x00: str="ETSI allocated address"; break;
		case 0x01: str="IETF allocated address"; break;
		case 0x0f: str="Empty PDP type"; break;
		default: str="reserved";
	}

	proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"PDP type organisation: (%u) %s",oct&0x0f,str);

	oct2 = tvb_get_guint8(tvb, curr_offset+1);

	if (( oct&0x0f ) == 0 )
	{
		switch ( oct2 )
		{
			case 0x00: str="Reserved, used in earlier version of this protocol"; break;
			case 0x01: str="PDP-type PPP"; break;
			default: str="reserved";
		}
	}
	else if (( oct&0x0f) == 1 )
	{
		switch ( oct2 )
		{
			case 0x21: str="IPv4 address"; break;
			case 0x57: str="IPv6 address"; break;
			default: str="IPv4 address";
		}
	}
	else if ((oct2==0) && (( oct&0x0f) == 0x0f ))
		str="Empty";
	else
		str="Not specified";	

	proto_tree_add_text(tree,
		tvb, curr_offset+1, 1,
		"PDP type number: (%u) %s",oct2,str);

	if (( len == 2 ) && (( oct2 == 0x21 ) || ( oct2 == 0x57 )))
	{
		proto_tree_add_text(tree,
			tvb, curr_offset+1, 1,
			"Dynamic addressing");

		curr_offset+= curr_len;

		EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

		return(curr_offset - offset);
	}
	else if ( len == 2 )
	{
		proto_tree_add_text(tree,
			tvb, curr_offset+1, 1,
			"No PDP address is included");

		curr_offset+= curr_len;

		EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

		return(curr_offset - offset);
	}
	else if ( len < 2 )
	{
		proto_tree_add_text(tree,
			tvb, curr_offset+1, 1,
			"Length is bogus - should be >= 2");

		curr_offset+= curr_len;

		EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

		return(curr_offset - offset);
	}

	if ((( oct2 == 0x21 ) && ( len != 6 )) ||
	   (( oct2 == 0x57 ) && ( len != 18 )))
	{
		proto_tree_add_text(tree,
			tvb, curr_offset+2, len-2,
			"Can't display address");
	}

	switch ( oct2 )
	{
		case 0x21:
			if (len-2 != 4) {
				proto_tree_add_text(tree,
				tvb, curr_offset+2, 0,
					"IPv4: length is wrong");
			} else {
				proto_tree_add_text(tree,
					tvb, curr_offset+2, len-2,
					"IPv4: %s", ip_to_str(tvb_get_ptr(tvb, offset+2, 4)));
			}
			break;

		case 0x57:
			if (len-2 != 16) {
				proto_tree_add_text(tree,
					tvb, curr_offset+2, 0,
					"IPv6: length is wrong");
			} else {
				tvb_get_ipv6(tvb, curr_offset+2, &ipv6_addr);
				proto_tree_add_text(tree,
					tvb, curr_offset+2, len-2,
					"IPv6: %s", ip6_to_str(&ipv6_addr));
			}
			break;
	}

	curr_offset+= curr_len;
	
	EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

	return(curr_offset - offset);
}

/*
 * [7] 10.5.6.5 3GPP TS 24.008 version 7.8.0 Release 7
 */

static const value_string gsm_a_qos_delay_cls_vals[] = {
	{ 0x00, "Subscribed delay class (in MS to network direction)" },
	{ 0x01, "Delay class 1" },
	{ 0x02, "Delay class 2" },
	{ 0x03, "Delay class 3" },
	{ 0x04, "Delay class 4 (best effort)" },
	{ 0x07,	"Reserved" },
	{ 0, NULL }
};

static const value_string gsm_a_qos_reliability_vals[] = {
	{ 0x00, "Subscribed reliability class (in MS to network direction)" },
	{ 0x01, "Acknowledged GTP, LLC, and RLC; Protected data" },
	{ 0x02, "Unacknowledged GTP, Ack LLC/RLC, Protected data" },
	{ 0x03, "Unacknowledged GTP/LLC, Ack RLC, Protected data" },
	{ 0x04, "Unacknowledged GTP/LLC/RLC, Protected data" },
	{ 0x05, "Unacknowledged GTP/LLC/RLC, Unprotected data" },
	{ 0x07, "Reserved" },
	{ 0, NULL }
};
 /* Delivery of erroneous SDUs, octet 6 (see 3GPP TS 23.107) Bits 3 2 1 */
const value_string gsm_a_qos_del_of_err_sdu_vals[] = {
	{ 0, "Subscribed delivery of erroneous SDUs/Reserved" },
	{ 1, "No detect('-')" },
	{ 2, "Erroneous SDUs are delivered('yes')" },
	{ 3, "Erroneous SDUs are not delivered('No')" },
	{ 7, "Reserved" },
	{ 0, NULL }
};

 /* Delivery order, octet 6 (see 3GPP TS 23.107) Bits 5 4 3 */
const value_string gsm_a_qos_del_order_vals[] = {
	{ 0, "Subscribed delivery order/Reserved" },
	{ 1, "With delivery order ('yes')" },
	{ 2, "Without delivery order ('no')" },
	{ 3, "Reserved" },
	{ 0, NULL }
};
/* Traffic class, octet 6 (see 3GPP TS 23.107) Bits 8 7 6 */
const value_string gsm_a_qos_traffic_cls_vals[] = {
	{ 0, "Subscribed traffic class/Reserved" },
	{ 1, "Conversational class" },
	{ 2, "Streaming class" },
	{ 3, "Interactive class" },
	{ 4, "Background class" },
	{ 7, "Reserved" },
	{ 0, NULL }
};

/* Residual Bit Error Rate (BER), octet 10 (see 3GPP TS 23.107) Bits 8 7 6 5 */
const value_string gsm_a_qos_ber_vals[] = {
	{ 0, "Subscribed residual BER/Reserved" },
	{ 1, "5*10-2" },
	{ 2, "1*10-2" },
	{ 3, "5*10-3" },
	{ 4, "4*10-3" },
	{ 5, "1*10-3" },
	{ 6, "1*10-4" },
	{ 7, "1*10-5" },
	{ 8, "1*10-6" },
	{ 9, "6*10-8" },
	{ 10, "Reserved" },
	{ 0, NULL }
};

/* SDU error ratio, octet 10 (see 3GPP TS 23.107) Bits 4 3 2 1 */
const value_string gsm_a_qos_sdu_err_rat_vals[] = {
	{ 0, "Subscribed SDU error ratio/Reserved" },
	{ 1, "1*10-2" },
	{ 2, "7*10-3" },
	{ 3, "1*10-3" },
	{ 4, "1*10-4" },
	{ 5, "1*10-5" },
	{ 6, "1*10-6" },
	{ 7, "1*10-1" },
	{ 15, "Reserved" },
	{ 0, NULL }
};

/* Traffic handling priority, octet 11 (see 3GPP TS 23.107) Bits 2 1 */
const value_string gsm_a_qos_traff_hdl_pri_vals[] = {
	{ 0, "Subscribed traffic handling priority/Reserved" },
	{ 1, "Priority level 1" },
	{ 2, "Priority level 2" },
	{ 3, "Priority level 3" },
	{ 0, NULL }
};

guint16
de_sm_qos(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;
	guint	curr_len;
	guchar	   oct, tmp_oct;
	const gchar	*str;

	curr_len = len;
	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	proto_tree_add_item(tree, hf_gsm_a_qos_delay_cls, tvb, curr_offset, 1, FALSE);
	proto_tree_add_item(tree, hf_gsm_a_qos_qos_reliability_cls, tvb, curr_offset, 1, FALSE);

	curr_offset+= 1;
	curr_len-= 1;

	if ( curr_len == 0 )
	{
		EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

		return(curr_offset - offset);
	}

	oct = tvb_get_guint8(tvb, curr_offset);

	switch ( oct>>4 )
	{
		case 0x00: str="Subscribed peak throughput/reserved"; break;
		case 0x01: str="Up to 1 000 octet/s"; break;
		case 0x02: str="Up to 2 000 octet/s"; break;
		case 0x03: str="Up to 4 000 octet/s"; break;
		case 0x04: str="Up to 8 000 octet/s"; break;
		case 0x05: str="Up to 16 000 octet/s"; break;
		case 0x06: str="Up to 32 000 octet/s"; break;
		case 0x07: str="Up to 64 000 octet/s"; break;
		case 0x08: str="Up to 128 000 octet/s"; break;
		case 0x09: str="Up to 256 000 octet/s"; break;
		case 0x0f: str="Reserved"; break;
		default: str="Up to 1 000 octet/s";
	}

	proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"Peak throughput: (%u) %s",oct>>4,str);

	switch ( oct&0x7 )
	{
		case 0x00: str="Subscribed precedence/reserved"; break;
		case 0x01: str="High priority"; break;
		case 0x02: str="Normal priority"; break;
		case 0x03: str="Low priority"; break;
		case 0x07: str="Reserved"; break;
		default: str="Normal priority";
	}

	proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"Precedence class: (%u) %s",oct&7,str);

	curr_offset+= 1;
	curr_len-= 1;

	if ( curr_len == 0 )
	{
		EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

		return(curr_offset - offset);
	}

	oct = tvb_get_guint8(tvb, curr_offset);

	switch ( oct&0x1f )
	{
		case 0x00: str="Subscribed peak throughput/reserved"; break;
		case 0x01: str="100 octet/h"; break;
		case 0x02: str="200 octet/h"; break;
		case 0x03: str="500 octet/h"; break;
		case 0x04: str="1 000 octet/h"; break;
		case 0x05: str="2 000 octet/h"; break;
		case 0x06: str="5 000 octet/h"; break;
		case 0x07: str="10 000 octet/h"; break;
		case 0x08: str="20 000 octet/h"; break;
		case 0x09: str="50 000 octet/h"; break;
		case 0x0a: str="100 000 octet/h"; break;
		case 0x0b: str="200 000 octet/h"; break;
		case 0x0c: str="500 000 octet/h"; break;
		case 0x0d: str="1 000 000 octet/h"; break;
		case 0x0e: str="2 000 000 octet/h"; break;
		case 0x0f: str="5 000 000 octet/h"; break;
		case 0x10: str="10 000 000 octet/h"; break;
		case 0x11: str="20 000 000 octet/h"; break;
		case 0x12: str="50 000 000 octet/h"; break;
		case 0x1e: str="Reserved"; break;
		case 0x1f: str="Best effort"; break;
		default: str="Best effort";
	}

	proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"Mean throughput: (%u) %s",oct&0x1f,str);

	curr_offset+= 1;
	curr_len-= 1;

	if ( curr_len == 0 )
	{
		EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

		return(curr_offset - offset);
	}

	proto_tree_add_item(tree, hf_gsm_a_qos_traffic_cls, tvb, curr_offset, 1, FALSE);
	proto_tree_add_item(tree, hf_gsm_a_qos_del_order, tvb, curr_offset, 1, FALSE);
	proto_tree_add_item(tree, hf_gsm_a_qos_del_of_err_sdu, tvb, curr_offset, 1, FALSE);

	curr_offset+= 1;
	curr_len-= 1;

	if ( curr_len == 0 )
	{
		EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

		return(curr_offset - offset);
	}

	oct = tvb_get_guint8(tvb, curr_offset);

	switch ( oct )
	{
		case 0x00: str="Subscribed maximum SDU size/reserved"; break;
		case 0x97: str="1502 octets"; break;
		case 0x98: str="1510 octets"; break;
		case 0x99: str="1520 octets"; break;
		case 0xff: str="Reserved"; break;
		default: str="Unspecified";
	}

	if (( oct >= 1 ) && ( oct <= 0x96 ))
		proto_tree_add_text(tree,
			tvb, curr_offset, 1,
			"Maximum SDU size: (%u) %u octets",oct,oct*10);
	else
		proto_tree_add_text(tree,
			tvb, curr_offset, 1,
			"Maximum SDU size: (%u) %s",oct,str);

	curr_offset+= 1;
	curr_len-= 1;

	if ( curr_len == 0 )
	{
		EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

		return(curr_offset - offset);
	}

	oct = tvb_get_guint8(tvb, curr_offset);

	switch ( oct )
	{
		case 0x00: str="Subscribed maximum bit rate for uplink/reserved"; break;
		case 0xff: str="0kbps"; break;
		default: str="This should not happen - BUG";
	}

	if (( oct >= 1 ) && ( oct <= 0x3f ))
		proto_tree_add_text(tree,
			tvb, curr_offset, 1,
			"Maximum bit rate for uplink: (%u) %ukbps",oct,oct);
	else if (( oct >= 0x40 ) && ( oct <= 0x7f ))
		proto_tree_add_text(tree,
			tvb, curr_offset, 1,
			"Maximum bit rate for uplink: (%u) %ukbps",oct,(oct-0x40)*8+64); /* - was (oct-0x40)*8  */
	else if (( oct >= 0x80 ) && ( oct <= 0xfe ))
		proto_tree_add_text(tree,
			tvb, curr_offset, 1,
			"Maximum bit rate for uplink: (%u) %ukbps",oct,(oct-0x80)*64+576); /* - was (oct-0x80)*64 */
	else
		proto_tree_add_text(tree,
			tvb, curr_offset, 1,
			"Maximum bit rate for uplink: (%u) %s",oct,str);

	curr_offset+= 1;
	curr_len-= 1;

	if ( curr_len == 0 )
	{
		EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

		return(curr_offset - offset);
	}

	oct = tvb_get_guint8(tvb, curr_offset);

	switch ( oct )
	{
		case 0x00: str="Subscribed maximum bit rate for uplink/reserved"; break;
		case 0xff: str="0kbps"; break;
		default: str="This should not happen - BUG";
	}

	if (( oct >= 1 ) && ( oct <= 0x3f ))
		proto_tree_add_text(tree,
			tvb, curr_offset, 1,
		"Maximum bit rate for downlink: (%u) %ukbps",oct,oct);
	else if (( oct >= 0x40 ) && ( oct <= 0x7f ))
		proto_tree_add_text(tree,
			tvb, curr_offset, 1,
			"Maximum bit rate for downlink: (%u) %ukbps",oct,(oct-0x40)*8+64);/*same as above*/
	else if (( oct >= 0x80 ) && ( oct <= 0xfe ))
		proto_tree_add_text(tree,
			tvb, curr_offset, 1,
			"Maximum bit rate for downlink: (%u) %ukbps",oct,(oct-0x80)*64+576);/*same as above*/
	else
		proto_tree_add_text(tree,
			tvb, curr_offset, 1,
			"Maximum bit rate for downlink: (%u) %s",oct,str);

	curr_offset+= 1;
	curr_len-= 1;

	if ( curr_len == 0 )
	{
		EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

		return(curr_offset - offset);
	}

	/* Octet 10 */
	proto_tree_add_item(tree, hf_gsm_a_qos_ber, tvb, curr_offset, 1, FALSE);
	proto_tree_add_item(tree, hf_gsm_a_qos_sdu_err_rat, tvb, curr_offset, 1, FALSE);

	curr_offset+= 1;
	curr_len-= 1;

	if ( curr_len == 0 )
	{
		EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

		return(curr_offset - offset);
	}

	/* Octet 11 */
	oct = tvb_get_guint8(tvb, curr_offset);

	switch ( oct>>2 )
	{
		case 0x00: str="Subscribed transfer delay/reserved"; break;
		case 0x3f: str="Reserved"; break;
		default: str="This should not happen - BUG";
	}

	tmp_oct = oct>>2;

	if (( tmp_oct >= 1 ) && ( tmp_oct <= 0x0f ))
		proto_tree_add_text(tree,
			tvb, curr_offset, 1,
			"Transfer Delay: (%u) %ums",oct>>2,(oct>>2)*10);
	else if (( tmp_oct >= 0x10 ) && ( tmp_oct <= 0x1f ))
		proto_tree_add_text(tree,
			tvb, curr_offset, 1,
			"Transfer Delay: (%u) %ums",oct>>2,((oct>>2)-0x10)*50+200);
	else if (( tmp_oct >= 0x20 ) && ( tmp_oct <= 0x3e ))
		proto_tree_add_text(tree,
			tvb, curr_offset, 1,
			"Transfer Delay: (%u) %ums",oct>>2,((oct>>2)-0x20)*100+1000);
	else
		proto_tree_add_text(tree,
			tvb, curr_offset, 1,
			"Transfer Delay: (%u) %s",oct>>2,str);

	switch ( oct&0x03 )
	{
		case 0x00: str="Subscribed traffic handling priority/reserved"; break;
		case 0x01: str="Priority level 1"; break;
		case 0x02: str="Priority level 2"; break;
		case 0x03: str="Priority level 3"; break;
		default: str="This should not happen - BUG";
	}

	proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"Traffic Handling priority: (%u) %s",oct&0x03,str);

	curr_offset+= 1;
	curr_len-= 1;

	if ( curr_len == 0 )
	{
		EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

		return(curr_offset - offset);
	}

	/* Octet 12 */
	oct = tvb_get_guint8(tvb, curr_offset);

	switch ( oct )
	{
		case 0x00: str="Subscribed guaranteed bit rate for uplink/reserved"; break;
		case 0xff: str="0kbps"; break;
		default: str="This should not happen - BUG";
	}

	if (( oct >= 1 ) && ( oct <= 0x3f ))
		proto_tree_add_text(tree,
			tvb, curr_offset, 1,
			"Guaranteed bit rate for uplink: (%u) %ukbps",oct,oct);
	else if (( oct >= 0x40 ) && ( oct <= 0x7f ))
		proto_tree_add_text(tree,
			tvb, curr_offset, 1,
			"Guaranteed bit rate for uplink: (%u) %ukbps",oct,(oct-0x40)*8+64);/*same as for max bit rate*/
	else if (( oct >= 0x80 ) && ( oct <= 0xfe ))
		proto_tree_add_text(tree,
			tvb, curr_offset, 1,
			"Guaranteed bit rate for uplink: (%u) %ukbps",oct,(oct-0x80)*64+576);/*same as for max bit rate*/
	else
		proto_tree_add_text(tree,
			tvb, curr_offset, 1,
			"Guaranteed bit rate for uplink: (%u) %s",oct,str);

	curr_offset+= 1;
	curr_len-= 1;

	if ( curr_len == 0 )
	{
		EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

		return(curr_offset - offset);
	}

	oct = tvb_get_guint8(tvb, curr_offset);

	switch ( oct )
	{
		case 0x00: str="Subscribed guaranteed bit rate for uplink/reserved"; break;
		case 0xff: str="0kbps"; break;
		default: str="This should not happen - BUG";
	}

	if (( oct >= 1 ) && ( oct <= 0x3f ))
		proto_tree_add_text(tree,
			tvb, curr_offset, 1,
			"Guaranteed bit rate for downlink: (%u) %ukbps",oct,oct);
	else if (( oct >= 0x40 ) && ( oct <= 0x7f ))
		proto_tree_add_text(tree,
			tvb, curr_offset, 1,
			"Guaranteed bit rate for downlink: (%u) %ukbps",oct,(oct-0x40)*8+64);/*same as above*/
	else if (( oct >= 0x80 ) && ( oct <= 0xfe ))
		proto_tree_add_text(tree,
			tvb, curr_offset, 1,
			"Guaranteed bit rate for downlink: (%u) %ukbps",oct,(oct-0x80)*64+576);/*same as above*/
	else
		proto_tree_add_text(tree,
			tvb, curr_offset, 1,
			"Guaranteed bit rate for downlink: (%u) %s",oct,str);

	curr_offset+= 1;
	curr_len-= 1;

	if ( curr_len == 0 )
	{
		EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

		return(curr_offset - offset);
	}

	/* Ocet 14 */
	oct = tvb_get_guint8(tvb, curr_offset);

	switch ( (oct>>4)&1 )
	{
		case 0x00: str="Not optimised for signalling traffic"; break;
		case 0x01: str="Optimised for signalling traffic"; break;
		default: str="This should not happen - BUG";
	}

	proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"Signalling Indication: (%u) %s",(oct>>4)&1,str);

	switch ( oct&7 )
	{
		case 0x00: str="unknown"; break;
		case 0x01: str="speech"; break;
		default: str="unknown";
	}

	proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"Source Statistics Descriptor: (%u) %s",oct&7,str);

	curr_offset+= 1;
	curr_len-= 1;

	if ( curr_len == 0 )
	{
		EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

		return(curr_offset - offset);
	}

	/* Octet 15 */

	oct = tvb_get_guint8(tvb, curr_offset);

	switch ( oct )
	{
		case 0x00: str="Use the value indicated by the Maximum bit rate for downlink"; break;
		default: str="Unspecified";
	}

	if (( oct >= 1 ) && ( oct <= 0x4a ))
		proto_tree_add_text(tree,
			tvb, curr_offset, 1,
			"Maximum bit rate for downlink (extended): (%u) %ukbps",oct,oct*100);
	if (( oct >= 0x4b ) && ( oct <= 0xba ))
		proto_tree_add_text(tree,
			tvb, curr_offset, 1,
			"Maximum bit rate for downlink (extended): (%u) %uMbps",oct,16 + oct- 0x4a);
	if (( oct >= 0xbb ) && ( oct <= 0xfa ))
		proto_tree_add_text(tree,
			tvb, curr_offset, 1,
			"Maximum bit rate for downlink (extended): (%u) %uMbps",oct,128 + oct - 0xba * 2);
	else
		proto_tree_add_text(tree,
			tvb, curr_offset, 1,
			"Maximum bit rate for downlink (extended): (%u) %s",oct,str);

	curr_offset+= 1;
	curr_len-= 1;

	if ( curr_len == 0 )
	{
		EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

		return(curr_offset - offset);
	}

	/* Octet 16 */
	oct = tvb_get_guint8(tvb, curr_offset);

	switch ( oct )
	{
		case 0x00: str="Use the value indicated by the Guaranteed bit rate for downlink"; break;
		default: str="Unspecified";
	}

	if (( oct >= 1 ) && ( oct <= 0x4a ))
		proto_tree_add_text(tree,
			tvb, curr_offset, 1,
			"Guaranteed bit rate for downlink (extended): (%u) %ukbps",oct,oct*100);
	if (( oct >= 0x4b ) && ( oct <= 0xba ))
		proto_tree_add_text(tree,
			tvb, curr_offset, 1,
			"Guaranteed bit rate for downlink (extended): (%u) %uMbps",oct,16 + oct- 0x4a);
	if (( oct >= 0xbb ) && ( oct <= 0xfa ))
		proto_tree_add_text(tree,
			tvb, curr_offset, 1,
			"Guaranteed bit rate for downlink (extended): (%u) %uMbps",oct,128 + oct - 0xba * 2);
	else
		proto_tree_add_text(tree,
			tvb, curr_offset, 1,
			"Guaranteed bit rate for downlink (extended): (%u) %s",oct,str);

	curr_offset+= 1;
	curr_len-= 1;

	if ( curr_len == 0 )
	{
		EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

		return(curr_offset - offset);
	}
	/* Maximum bit rate for uplink (extended) Octet 17 */
	oct = tvb_get_guint8(tvb, curr_offset);

	switch ( oct )
	{
		case 0x00: str="Use the value indicated by the Maximum bit rate for uplink"; break;
		default: str="Unspecified";
	}

	if (( oct >= 1 ) && ( oct <= 0x4a ))
		proto_tree_add_text(tree,
			tvb, curr_offset, 1,
			"Maximum bit rate for uplink (extended): (%u) %ukbps",oct,oct*100);
	if (( oct >= 0x4b ) && ( oct <= 0xba ))
		proto_tree_add_text(tree,
			tvb, curr_offset, 1,
			"Maximum bit rate for uplink (extended): (%u) %uMbps",oct,16 + oct- 0x4a);
	if (( oct >= 0xbb ) && ( oct <= 0xfa ))
		proto_tree_add_text(tree,
			tvb, curr_offset, 1,
			"Maximum bit rate for uplink (extended): (%u) %uMbps",oct,128 + oct - 0xba * 2);
	else
		proto_tree_add_text(tree,
			tvb, curr_offset, 1,
			"Maximum bit rate for uplink (extended): (%u) %s",oct,str);

	curr_offset+= 1;
	curr_len-= 1;

	if ( curr_len == 0 )
	{
		EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

		return(curr_offset - offset);
	}

	/* Guaranteed bit rate for uplink (extended) Octet 18 */
	oct = tvb_get_guint8(tvb, curr_offset);

	switch ( oct )
	{
		case 0x00: str="Use the value indicated by the Guaranteed bit rate for uplink"; break;
		default: str="Unspecified";
	}

	if (( oct >= 1 ) && ( oct <= 0x4a ))
		proto_tree_add_text(tree,
			tvb, curr_offset, 1,
			"Guaranteed bit rate for uplink (extended): (%u) %ukbps",oct,oct*100);
	if (( oct >= 0x4b ) && ( oct <= 0xba ))
		proto_tree_add_text(tree,
			tvb, curr_offset, 1,
			"Guaranteed bit rate for uplink (extended): (%u) %uMbps",oct,16 + oct- 0x4a);
	if (( oct >= 0xbb ) && ( oct <= 0xfa ))
		proto_tree_add_text(tree,
			tvb, curr_offset, 1,
			"Guaranteed bit rate for uplink (extended): (%u) %uMbps",oct,128 + oct - 0xba * 2);
	else
		proto_tree_add_text(tree,
			tvb, curr_offset, 1,
			"Guaranteed bit rate for uplink (extended): (%u) %s",oct,str);

	curr_offset+= 1;
	curr_len-= 1;
	EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

	return(curr_offset - offset);
}

/*
 * [8] 10.5.6.6 SM cause
 */
static guint16
de_sm_cause(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string, int string_len _U_)
{
	guint8	oct;
	guint32	curr_offset;
	const gchar	*str;

	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	switch ( oct )
	{
		case 0x08: str="Operator Determined Barring"; break;
		case 0x18: str="MBMS bearer capabilities insufficient for the service"; break;
		case 0x19: str="LLC or SNDCP failure(GSM only)"; break;
		case 0x1a: str="Insufficient resources"; break;
		case 0x1b: str="Missing or unknown APN"; break;
		case 0x1c: str="Unknown PDP address or PDP type"; break;
		case 0x1d: str="User Authentication failed"; break;
		case 0x1e: str="Activation rejected by GGSN"; break;
		case 0x1f: str="Activation rejected, unspecified"; break;
		case 0x20: str="Service option not supported"; break;
		case 0x21: str="Requested service option not subscribed"; break;
		case 0x22: str="Service option temporarily out of order"; break;
		case 0x23: str="NSAPI already used (not sent)"; break;
		case 0x24: str="Regular deactivation"; break;
		case 0x25: str="QoS not accepted"; break;
		case 0x26: str="Network failure"; break;
		case 0x27: str="Reactivation required"; break;
		case 0x28: str="Feature not supported"; break;
		case 0x29: str="Semantic error in the TFT operation"; break;
		case 0x2a: str="Syntactical error in the TFT operation"; break;
		case 0x2b: str="Unknown PDP context"; break;
		case 0x2e: str="PDP context without TFT already activated"; break;
		case 0x2f: str="Multicast group membership time-out"; break;
		case 0x2c: str="Semantic errors in packet filter(s)"; break;
		case 0x2d: str="Syntactical errors in packet filter(s)"; break;
		case 0x51: str="Invalid transaction identifier value"; break;
		case 0x5f: str="Semantically incorrect message"; break;
		case 0x60: str="Invalid mandatory information"; break;
		case 0x61: str="Message type non-existent or not implemented"; break;
		case 0x62: str="Message type not compatible with the protocol state"; break;
		case 0x63: str="Information element non-existent or not implemented"; break;
		case 0x64: str="Conditional IE error"; break;
		case 0x65: str="Message not compatible with the protocol state"; break;
		case 0x6f: str="Protocol error, unspecified"; break;
		case 0x70: str="APN restriction value incompatible with active PDP context"; break;
		default: str="Protocol error, unspecified"; break;
	}

	proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"Cause: (%u) %s %s",
		oct, str,add_string ? add_string : "");

	curr_offset++;

	return(curr_offset - offset);
}

/*
 * [7] 10.5.6.7
 */
static guint16
de_sm_linked_ti(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;
	guint	curr_len;
	gchar	   oct;

	gchar	   ti_flag[2][80]={ "The message is sent from the side that originates the TI" ,
				"The message is sent to the side that originates the TI" };

	curr_len = len;
	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"TI flag: (%u) %s",oct>>7,ti_flag[oct>>7]);

	if ( curr_len > 1 )
	{
		oct = tvb_get_guint8(tvb, curr_offset);

		proto_tree_add_text(tree,
			tvb, curr_offset, 1,
			"TI value: 0x%02x (%u)",oct&0x7f,oct&0x7f);

		proto_tree_add_text(tree,
			tvb, curr_offset, 1,
			"ext: 0x%02x (%u)",oct>>7,oct>>7);

	}
	else
	{
		proto_tree_add_text(tree,
			tvb, curr_offset, 1,
			"TI value: 0x%02x (%u)",(oct>>4)&7,(oct>>4)&7);
	}

	curr_offset+= curr_len;
	   
	EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

	return(curr_offset - offset);
}

/*
 * [7] 10.5.6.9
 */
static guint16
de_sm_sapi(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string, int string_len _U_)
{
	guint8	oct;
	guint32	curr_offset;

	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"LLC SAPI: 0x%02x (%u) %s",
		oct&0x0f, oct&0x0f,add_string ? add_string : "");

	curr_offset++;

	return(curr_offset - offset);
}

/*
 * [7] 10.5.6.10
 */
static guint16
de_sm_tear_down(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string, int string_len _U_)
{
	guint8	oct;
	guint32	curr_offset;
	gchar	str[2][30] = { "tear down not requested" , "tear down requested" };

	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"Tear Down Indicator: (%u) %s %s",
		oct&1, str[oct&1],add_string ? add_string : "");

	curr_offset++;

	return(curr_offset - offset);
}

/*
 * [7] 10.5.6.11
 */
/* Packet Flow Identifier value (octet 3) */
static const value_string gsm_a_packet_flow_id_vals[] = {
	{ 0,		"Best Effort"},
	{ 1,		"Signaling"},
	{ 2,		"SMS"},
	{ 3,		"TOM8"},
	{ 4,		"reserved"},
	{ 5,		"reserved"},
	{ 6,		"reserved"},
	{ 7,		"reserved"},
	{ 0,	NULL }
};
guint16
de_sm_pflow_id(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;
	guint	curr_len;
	guchar	oct;

	curr_len = len;
	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	proto_tree_add_text(tree,
		tvb, curr_offset, 1,
		"Packet Flow Identifier: (%u) %s",oct&0x7f,
		val_to_str(oct&0x7f, gsm_a_packet_flow_id_vals, "dynamically assigned (%u)"));

	curr_offset+= curr_len;
	   
	EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

	return(curr_offset - offset);
}

/*
 * [7] 10.5.6.12     TFT - Traffic Flow Template
 */
/* TFT operation code (octet 3) */
static const value_string gsm_a_tft_op_code_vals[] = {
	{ 0,		"Spare"},
	{ 1,		"Create new TFT"},
	{ 2,		"Delete existing TFT"},
	{ 3,		"Add packet filters to existing TFT"},
	{ 4,		"Replace packet filters in existing TFT"},
	{ 5,		"Delete packet filters from existing TFT"},
	{ 6,		"No TFT operation"},
	{ 7,		"Reserved"},
	{ 0,	NULL }
};

static const true_false_string gsm_a_tft_e_bit  = {
  "parameters list is included",
  "parameters list is not included"
};


static guint16
de_sm_tflow_temp(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;
	guint	curr_len;
	proto_item	*tf = NULL;
	proto_tree	*tf_tree = NULL;
	proto_tree	*comp_tree = NULL;
	guchar	op_code;
	guchar	pkt_fil_count;
	guchar	e_bit;
	const gchar	*str;
	guchar	count;
	guchar	oct;
	gint	pf_length;
	gint	pf_identifier;
	gint	pack_component_type;

	curr_len = len;
	curr_offset = offset;

	/*
	 * parse first octet. It contain TFT operation code, E bit and Number of packet filters
	 */
	oct = tvb_get_guint8(tvb, curr_offset);

	op_code = oct>>5;
	pkt_fil_count = oct&0x0f;
	e_bit = (oct>>4)&1;

	proto_tree_add_item(tree,hf_gsm_a_tft_op_code,tvb,curr_offset,1,FALSE);
	proto_tree_add_item(tree,hf_gsm_a_tft_e_bit,tvb,curr_offset,1,FALSE);
	proto_tree_add_item(tree,hf_gsm_a_tft_pkt_flt,tvb,curr_offset,1,FALSE);

	curr_offset++;
	curr_len--;

	/* Packet filter list dissect */

	count = 0;
	if ( op_code == 2 )			/* delete TFT contains no packet filters. so we will jump over it */
		count = pkt_fil_count;
	while ( count < pkt_fil_count )
	{
		tf = proto_tree_add_text(tree,
			tvb, curr_offset, 1,
			"Packet filter %d",count);   /* 0-> 7 */

		tf_tree = proto_item_add_subtree(tf, ett_sm_tft );

		if ( op_code == 5 )  /* Delete packet filters from existing TFT - just a list of identifiers */
		{
			if ((curr_offset-offset)<1) {
				proto_tree_add_text(tf_tree,tvb, curr_offset, 1,"Not enough data");
				return(curr_offset-offset);
			}
			oct = tvb_get_guint8(tvb, curr_offset);
			curr_offset++;
			curr_len--;

			proto_tree_add_text(tf_tree,
				tvb, curr_offset-1, 1,
				"Packet filter identifier: 0x%02x (%u)",oct,oct );	
		}
		else				/* create new, Add packet filters or Replace packet filters */
		{

			if ((curr_offset-offset)<1) {
				proto_tree_add_text(tf_tree,tvb, curr_offset, 1,"Not enough data");
				return(curr_offset-offset);
			}
			pf_identifier = tvb_get_guint8(tvb, curr_offset);
			curr_offset++;
			curr_len--;

			proto_tree_add_text(tf_tree,
				tvb, curr_offset-1, 1,
				"Packet filter identifier: %u (%u)",pf_identifier, pf_identifier);	

			if ((curr_offset-offset)<1) {
				proto_tree_add_text(tf_tree,tvb, curr_offset, 1,"Not enough data");
				return(curr_offset-offset);
			}
			oct = tvb_get_guint8(tvb, curr_offset);
			curr_offset++;
			curr_len--;

			proto_tree_add_text(tf_tree,
				tvb, curr_offset-1, 1,
				"Packet evaluation precedence: 0x%02x (%u)",oct,oct );	

			if ((curr_offset-offset)<1) { proto_tree_add_text(tf_tree,tvb, curr_offset, 1,"Not enough data"); return(curr_offset-offset);}
			pf_length = tvb_get_guint8(tvb, curr_offset);
			curr_offset++;
			curr_len--;

			proto_tree_add_text(tf_tree,
				tvb, curr_offset-1, 1,
				"Packet filter length: 0x%02x (%u)",pf_length,pf_length );	
			/* New tree for component */

			/* Dissect Packet filter Component */
			/* while ( filter_len > 1 ) */
			/* packet filter component type identifier: */

			if (pf_length > 0 ){
				if ((curr_offset-offset)<1) {
					proto_tree_add_text(tf_tree,tvb, curr_offset, 1,"Not enough data");
					return(curr_offset-offset);
				}
				pack_component_type = tvb_get_guint8(tvb, curr_offset);
				curr_offset++;
				curr_len--;

				tf=proto_tree_add_text(tf_tree,tvb, curr_offset-1, 1,"Packet filter component type identifier: ");
				comp_tree = proto_item_add_subtree(tf, ett_sm_tft );

				switch ( pack_component_type ){
			
				case 0x10:
					str="IPv4 source address type";
					proto_tree_add_item(comp_tree,hf_gsm_a_tft_ip4_address,tvb,curr_offset,4,FALSE);
					curr_offset+=4;
					curr_len-=4;
					proto_tree_add_item(comp_tree,hf_gsm_a_tft_ip4_mask,tvb,curr_offset,4,FALSE);
					curr_offset+=4;
					curr_len-=4;
					break;

				case 0x20:
					str="IPv6 source address type";
					proto_tree_add_item(comp_tree,hf_gsm_a_tft_ip6_address,tvb,curr_offset,16,FALSE);
					curr_offset+=16;
					curr_len-=16;
					proto_tree_add_item(comp_tree,hf_gsm_a_tft_ip6_mask,tvb,curr_offset,16,FALSE);
					curr_offset+=16;
					curr_len-=16;
					break;

				case 0x30:
					str="Protocol identifier/Next header type";
					proto_tree_add_item(comp_tree,hf_gsm_a_tft_protocol_header,tvb,curr_offset,1,FALSE);
					curr_offset+=1;
					curr_len-=1;
					break;

				case 0x40:
					str="Single destination port type";
					proto_tree_add_item(comp_tree,hf_gsm_a_tft_port,tvb,curr_offset,2,FALSE);
					curr_offset+=2;
					curr_len-=2;

				case 0x41:
					str="Destination port range type";
					proto_tree_add_item(comp_tree,hf_gsm_a_tft_port_low,tvb,curr_offset,2,FALSE);
					proto_tree_add_item(comp_tree,hf_gsm_a_tft_port_high,tvb,curr_offset,2,FALSE);
					curr_offset+=4;
					curr_len-=4;
					break;

				case 0x50:
					str="Single source port type";
					proto_tree_add_item(comp_tree,hf_gsm_a_tft_port,tvb,curr_offset,2,FALSE);
					curr_offset+=2;
					curr_len-=2;
					break;

				case 0x51:
					str="Source port range type";
					proto_tree_add_item(comp_tree,hf_gsm_a_tft_port_low,tvb,curr_offset,2,FALSE);
					proto_tree_add_item(comp_tree,hf_gsm_a_tft_port_high,tvb,curr_offset,2,FALSE);
					curr_offset+=4;
					curr_len-=4;
					break;

				case 0x60:
					str="Security parameter index type";
					proto_tree_add_item(comp_tree,hf_gsm_a_tft_security,tvb,curr_offset,4,FALSE);
					curr_offset+=4;
					curr_len-=4;
					break;


				case 0x70:
					str="Type of service/Traffic class type";
					proto_tree_add_item(comp_tree,hf_gsm_a_qos_traffic_cls,tvb,curr_offset,1,FALSE);
					proto_tree_add_item(comp_tree,hf_gsm_a_tft_traffic_mask,tvb,curr_offset,1,FALSE);
					curr_offset+=2;
					curr_len-=2;
					break;

				case 0x80:
					str="Flow label type";
					proto_tree_add_item(comp_tree,hf_gsm_a_tft_traffic_mask,tvb,curr_offset,1,FALSE);
					curr_offset+=3;
					curr_len-=3;
					break;

				default:
					str="not specified";
				}
				proto_item_append_text(tf, "(%u) %s", pack_component_type, str );
				count++;
			}
		}
	}

	/* The parameters list contains a variable number of parameters that might need to be
	 * transferred in addition to the packet filters. If the parameters list is included, the E
	 * bit is set to 1; otherwise, the E bit is set to 0.
	 */
	if (e_bit == 1){
		 proto_tree_add_text(tf_tree, tvb, curr_offset, 1, "Note: Possible Authorization Token/Flow Identifier not decoded yet");
	}
	return(curr_offset - offset);
}

guint16 (*gm_elem_fcn[])(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len) = {
	/* GPRS Mobility Management Information Elements 10.5.5 */
	de_gmm_attach_res,	/* Attach Result */
	de_gmm_attach_type,	/* Attach Type */
	de_gmm_ciph_alg,	/* Cipher Algorithm */
	de_gmm_tmsi_stat,	/* TMSI Status */
	de_gmm_detach_type,	/* Detach Type */
	de_gmm_drx_param,	/* DRX Parameter */
	de_gmm_ftostby,	/* Force to Standby */
	de_gmm_ftostby_h,	/* Force to Standby - Info is in the high nibble */
	de_gmm_ptmsi_sig,	/* P-TMSI Signature */
	de_gmm_ptmsi_sig2,	/* P-TMSI Signature 2 */
	de_gmm_ident_type2,	/* Identity Type 2 */
	de_gmm_imeisv_req,	/* IMEISV Request */
	de_gmm_rec_npdu_lst,	/* Receive N-PDU Numbers List */
	de_gmm_ms_net_cap,	/* MS Network Capability */
	de_gmm_ms_radio_acc_cap,	/* MS Radio Access Capability */
	de_gmm_cause,				/* GMM Cause */
	de_gmm_rai,					/* Routing Area Identification */
	de_gmm_update_res,	/* Update Result */
	de_gmm_update_type,	/* Update Type */
	de_gmm_ac_ref_nr,	/* A&C Reference Number */
	de_gmm_ac_ref_nr_h, /* A&C Reference Numer - Info is in the high nibble */
	de_gmm_service_type,	/* Service Type */
	de_gmm_cell_notfi,	/* Cell Notification */
	de_gmm_ps_lcs_cap,	/* PS LCS Capability */
	de_gmm_net_feat_supp,	/* Network Feature Support */
	de_gmm_rat_info_container, /* Inter RAT information container */
	/* Session Management Information Elements 10.5.6 */
	de_sm_apn,	/* Access Point Name */
	de_sm_nsapi,	/* Network Service Access Point Identifier */
	de_sm_pco,	/* Protocol Configuration Options */
	de_sm_pdp_addr,	/* Packet Data Protocol Address */
	de_sm_qos,	/* Quality Of Service */
	de_sm_cause,	/* SM Cause */
	de_sm_linked_ti,	/* Linked TI */
	de_sm_sapi,	/* LLC Service Access Point Identifier */
	de_sm_tear_down,	/* Tear Down Indicator */
	de_sm_pflow_id,	/* Packet Flow Identifier */
	de_sm_tflow_temp,	/* Traffic Flow Template */
	/* GPRS Common Information Elements 10.5.7 */
	de_gc_context_stat,	/* PDP Context Status */
	de_gc_radio_prio,	/* Radio Priority */
	de_gc_timer,	/* GPRS Timer */
	de_gc_timer2,	/* GPRS Timer 2 */
	de_gc_radio_prio2,	/* Radio Priority 2 */
	de_gc_mbms_context_stat, /* 10.5.7.6 MBMS context status */
	NULL,	/* NONE */
};

/* MESSAGE FUNCTIONS */

/*
 * [7] 9.4.1
 */
static void
dtap_gmm_attach_req(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	gsm_a_dtap_pinfo->p2p_dir = P2P_DIR_RECV;

	ELEM_MAND_LV(GSM_A_PDU_TYPE_GM, DE_MS_NET_CAP, "");

	/* Included in attach type

	ELEM_MAND_V(GSM_A_PDU_TYPE_COMMON, DE_CIPH_KEY_SEQ_NUM );
	curr_offset--;
	curr_len++;
	*/

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_ATTACH_TYPE );

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_DRX_PARAM );

	ELEM_MAND_LV(GSM_A_PDU_TYPE_COMMON, DE_MID , "" );

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_RAI );

	ELEM_MAND_LV(GSM_A_PDU_TYPE_GM, DE_MS_RAD_ACC_CAP , "" );

	ELEM_OPT_TV( 0x19 , GSM_A_PDU_TYPE_GM, DE_P_TMSI_SIG, " - Old P-TMSI Signature");

	ELEM_OPT_TV( 0x17 , GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER , " - Ready Timer" );

	ELEM_OPT_TV_SHORT( 0x90 , GSM_A_PDU_TYPE_GM, DE_TMSI_STAT , "" );

	ELEM_OPT_TLV( 0x33 , GSM_A_PDU_TYPE_GM, DE_PS_LCS_CAP , "" );

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [7] 9.4.2
 */
static void
dtap_gmm_attach_acc(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	gsm_a_dtap_pinfo->p2p_dir = P2P_DIR_SENT;

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_FORCE_TO_STAND_H );
	curr_len++;
	curr_offset--;

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_ATTACH_RES );

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER );

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_RAD_PRIO_2 );
	curr_len++;
	curr_offset--;

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_RAD_PRIO );

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_RAI );

	ELEM_OPT_TV( 0x19 , GSM_A_PDU_TYPE_GM, DE_P_TMSI_SIG, "" );

	ELEM_OPT_TV( 0x17 , GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER , " - Negotiated Ready Timer" );

	ELEM_OPT_TLV( 0x18 , GSM_A_PDU_TYPE_COMMON, DE_MID , " - Allocated P-TMSI" );

	ELEM_OPT_TLV( 0x23 , GSM_A_PDU_TYPE_COMMON, DE_MID , "" );

	ELEM_OPT_TV( 0x25 , GSM_A_PDU_TYPE_GM, DE_GMM_CAUSE , "" );

	ELEM_OPT_TLV( 0x2A , GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_2 , " - T3302" );

	ELEM_OPT_T( 0x8C , GSM_A_PDU_TYPE_GM, DE_CELL_NOT , "" );

	ELEM_OPT_TLV( 0x4A , GSM_A_PDU_TYPE_COMMON, DE_PLMN_LIST , "" );

	ELEM_OPT_TV_SHORT( 0xB0 , GSM_A_PDU_TYPE_GM, DE_NET_FEAT_SUP , "" );

	ELEM_OPT_TLV( 0x34 , GSM_A_PDU_TYPE_DTAP, DE_EMERGENCY_NUM_LIST , "" );

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [7] 9.4.3
 */
static void
dtap_gmm_attach_com(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{

	guint32	curr_offset;
/*    guint32	consumed; */
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	gsm_a_dtap_pinfo->p2p_dir = P2P_DIR_RECV;

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [7] 9.4.4
 */
static void
dtap_gmm_attach_rej(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	gsm_a_dtap_pinfo->p2p_dir = P2P_DIR_SENT;

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_GMM_CAUSE );

	ELEM_OPT_TLV( 0x2A , GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_2 , " - T3302" );

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [7] 9.4.5
 */
static void
dtap_gmm_detach_req(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	gsm_a_dtap_pinfo->p2p_dir = P2P_DIR_SENT;

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_FORCE_TO_STAND_H );
	/* Force to standy might be wrong - To decode it correct, we need the direction */
	curr_len++;
	curr_offset--;

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_DETACH_TYPE );

	ELEM_OPT_TV( 0x25 , GSM_A_PDU_TYPE_GM, DE_GMM_CAUSE , "" );

	ELEM_OPT_TLV( 0x18 , GSM_A_PDU_TYPE_COMMON, DE_MID , " - P-TMSI" );

	ELEM_OPT_TLV( 0x19 , GSM_A_PDU_TYPE_GM, DE_P_TMSI_SIG , "" );

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [7] 9.4.6
 */
static void
dtap_gmm_detach_acc(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	gsm_a_dtap_pinfo->p2p_dir = P2P_DIR_RECV;

	if ( curr_len != 0 )
	{
		ELEM_MAND_V(GSM_A_PDU_TYPE_COMMON, DE_SPARE_NIBBLE );
		curr_len++;
		curr_offset--;
	
		ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_FORCE_TO_STAND );
	}

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [7] 9.4.7
 */
static void
dtap_gmm_ptmsi_realloc_cmd(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	gsm_a_dtap_pinfo->p2p_dir = P2P_DIR_SENT;

	ELEM_MAND_LV(GSM_A_PDU_TYPE_COMMON, DE_MID , " - Allocated P-TMSI" );

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_RAI );

	ELEM_MAND_V(GSM_A_PDU_TYPE_COMMON, DE_SPARE_NIBBLE );
	curr_len++;
	curr_offset--;

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_FORCE_TO_STAND );

	ELEM_OPT_TV( 0x19 , GSM_A_PDU_TYPE_COMMON, DE_MID , " - P-TMSI Signature" );

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [7] 9.4.8
 */
static void
dtap_gmm_ptmsi_realloc_com(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
/*    guint32	consumed; */
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	gsm_a_dtap_pinfo->p2p_dir = P2P_DIR_RECV;

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [7] 9.4.9
 */
static void
dtap_gmm_auth_ciph_req(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;
	guint8      oct;

	curr_offset = offset;
	curr_len = len;

	gsm_a_dtap_pinfo->p2p_dir = P2P_DIR_SENT;

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_IMEISV_REQ );
	curr_offset--;
	curr_len++;

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_CIPH_ALG );

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_AC_REF_NUM_H );
	curr_offset--;
	curr_len++;

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_FORCE_TO_STAND );

	ELEM_OPT_TV( 0x21 , GSM_A_PDU_TYPE_DTAP, DE_AUTH_PARAM_RAND , "" );

#if 0
	ELEM_OPT_TV_SHORT( 0x08 , GSM_A_PDU_TYPE_COMMON, DE_CIPH_KEY_SEQ_NUM , "" );
#else
	if ( curr_len > 0 )
	{
		oct = tvb_get_guint8(tvb, curr_offset);
		if (( oct & 0xf0 ) == 0x80 )
		{
			/* The ciphering key sequence number is added here */
			proto_tree_add_text(tree,
				tvb, curr_offset, 1,
				"Ciphering key sequence number: 0x%02x (%u)",
				oct&7,
				oct&7);
			curr_offset++;
			curr_len--;
		}
	}
#endif

	if ( curr_len == 0  )
	{
		EXTRANEOUS_DATA_CHECK(curr_len, 0);
	return;
	}
	
	ELEM_OPT_TLV( 0x28 , GSM_A_PDU_TYPE_DTAP, DE_AUTH_PARAM_AUTN , "" );

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [7] 9.4.10
 */
static void
dtap_gmm_auth_ciph_resp(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	gsm_a_dtap_pinfo->p2p_dir = P2P_DIR_RECV;

	ELEM_MAND_V(GSM_A_PDU_TYPE_COMMON, DE_SPARE_NIBBLE );
	curr_offset--;
	curr_len++;

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_AC_REF_NUM );

	ELEM_OPT_TV( 0x22 , GSM_A_PDU_TYPE_DTAP, DE_AUTH_RESP_PARAM , "" );

	ELEM_OPT_TLV( 0x23 , GSM_A_PDU_TYPE_COMMON, DE_MID , " - IMEISV" );

	ELEM_OPT_TLV( 0x29 , GSM_A_PDU_TYPE_DTAP, DE_AUTH_RESP_PARAM_EXT , "" );

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [7] 9.4.11
 */
static void
dtap_gmm_auth_ciph_rej(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	gsm_a_dtap_pinfo->p2p_dir = P2P_DIR_SENT;

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [7] 9.4.10a
 */
static void
dtap_gmm_auth_ciph_fail(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	gsm_a_dtap_pinfo->p2p_dir = P2P_DIR_RECV;

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_GMM_CAUSE );

	ELEM_OPT_TLV( 0x30 , GSM_A_PDU_TYPE_DTAP, DE_AUTH_FAIL_PARAM , "" );

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [7] 9.4.12
 */
static void
dtap_gmm_ident_req(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	gsm_a_dtap_pinfo->p2p_dir = P2P_DIR_SENT;

/*  If the half octect that are about to get decoded is the LAST in the octetstream, the macro will call return BEFORE we get a chance to fix the index. The end result will be that the first half-octet will be decoded but not the last. */
/*    ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_ID_TYPE_2 );
	curr_offset--;
	curr_len++;
	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_FORCE_TO_STAND_H );*/

	elem_v(tvb, tree, GSM_A_PDU_TYPE_GM, DE_FORCE_TO_STAND_H, curr_offset);
	elem_v(tvb, tree, GSM_A_PDU_TYPE_GM, DE_ID_TYPE_2, curr_offset);

	curr_offset+=1;
	curr_len-=1;

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [7] 9.4.13
 */
static void
dtap_gmm_ident_res(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	gsm_a_dtap_pinfo->p2p_dir = P2P_DIR_RECV;

	ELEM_MAND_LV(GSM_A_PDU_TYPE_COMMON, DE_MID , "" );

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [7] 9.4.14
 */
static void
dtap_gmm_rau_req(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	gsm_a_dtap_pinfo->p2p_dir = P2P_DIR_RECV;

	/* is included in update type
	ELEM_MAND_V(GSM_A_PDU_TYPE_COMMON, DE_CIPH_KEY_SEQ_NUM );
	curr_offset--;
	curr_len++;
	*/

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_UPD_TYPE );

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_RAI );

	ELEM_MAND_LV(GSM_A_PDU_TYPE_GM, DE_MS_RAD_ACC_CAP , "" );

	ELEM_OPT_TV( 0x19 , GSM_A_PDU_TYPE_GM, DE_P_TMSI_SIG , " - Old P-TMSI Signature" );

	ELEM_OPT_TV( 0x17 , GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER , " - Requested Ready Timer" );

	ELEM_OPT_TV( 0x27 , GSM_A_PDU_TYPE_GM, DE_DRX_PARAM , "" );

	ELEM_OPT_TV_SHORT( 0x90 , GSM_A_PDU_TYPE_GM, DE_TMSI_STAT , "" );

	ELEM_OPT_TLV( 0x18 , GSM_A_PDU_TYPE_COMMON, DE_MID , " - P-TMSI" );

	ELEM_OPT_TLV( 0x31 , GSM_A_PDU_TYPE_GM, DE_MS_NET_CAP , "" );

	ELEM_OPT_TLV( 0x32 , GSM_A_PDU_TYPE_GM, DE_PDP_CONTEXT_STAT , "" );

	ELEM_OPT_TLV( 0x33 , GSM_A_PDU_TYPE_GM, DE_PS_LCS_CAP , "" );

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [7] 9.4.15
 */
static void
dtap_gmm_rau_acc(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	gsm_a_dtap_pinfo->p2p_dir = P2P_DIR_SENT;

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_UPD_RES );
	curr_offset--;
	curr_len++;

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_FORCE_TO_STAND );

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER );

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_RAI );

	ELEM_OPT_TV( 0x19 , GSM_A_PDU_TYPE_GM, DE_P_TMSI_SIG , "" );

	ELEM_OPT_TLV( 0x18 , GSM_A_PDU_TYPE_COMMON, DE_MID , " - Allocated P-TMSI");

	ELEM_OPT_TLV( 0x23 , GSM_A_PDU_TYPE_COMMON, DE_MID , "" );

	ELEM_OPT_TLV( 0x26 , GSM_A_PDU_TYPE_GM, DE_REC_N_PDU_NUM_LIST , "" );

	ELEM_OPT_TV( 0x17 , GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER , " - Negotiated Ready Timer" );

	ELEM_OPT_TV( 0x25 , GSM_A_PDU_TYPE_GM, DE_GMM_CAUSE , "" );

	ELEM_OPT_TLV( 0x2A , GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_2 , " - T3302" );

	ELEM_OPT_T( 0x8C , GSM_A_PDU_TYPE_GM, DE_CELL_NOT , "" );

	ELEM_OPT_TLV( 0x4A , GSM_A_PDU_TYPE_COMMON, DE_PLMN_LIST , "" );

	ELEM_OPT_TLV( 0x32 , GSM_A_PDU_TYPE_GM, DE_PDP_CONTEXT_STAT , "" );

	ELEM_OPT_TV_SHORT ( 0xB0 , GSM_A_PDU_TYPE_GM, DE_NET_FEAT_SUP , "" );

	ELEM_OPT_TLV( 0x34 , GSM_A_PDU_TYPE_DTAP, DE_EMERGENCY_NUM_LIST , "" );

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [7] 9.4.16
 */
static void
dtap_gmm_rau_com(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	gsm_a_dtap_pinfo->p2p_dir = P2P_DIR_RECV;
	/* [7] 10.5.5.11 */
	ELEM_OPT_TLV( 0x26 , GSM_A_PDU_TYPE_GM, DE_REC_N_PDU_NUM_LIST , "" );
	/* Inter RAT information container 10.5.5.24 TS 24.008 version 6.8.0 Release 6 */
	/*TO DO: Implement */
	ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_GM, DE_RAT_INFO_CONTAINER , "" );

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [7] 9.4.17
 */
static void
dtap_gmm_rau_rej(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	gsm_a_dtap_pinfo->p2p_dir = P2P_DIR_SENT;

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_GMM_CAUSE );

	ELEM_MAND_V(GSM_A_PDU_TYPE_COMMON, DE_SPARE_NIBBLE );
	curr_offset--;
	curr_len++;

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_FORCE_TO_STAND );

	ELEM_OPT_TLV( 0x26 , GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER_2 , " - T3302" );

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [7] 9.4.18
 */
static void
dtap_gmm_status(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	gsm_a_dtap_pinfo->p2p_dir = P2P_DIR_UNKNOWN;

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_GMM_CAUSE );

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [8] 9.4.19 GMM Information
 */
static void
dtap_gmm_information(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	gsm_a_dtap_pinfo->p2p_dir = P2P_DIR_SENT;

	ELEM_OPT_TLV( 0x43 , GSM_A_PDU_TYPE_DTAP, DE_NETWORK_NAME , " - Full Name" );

	ELEM_OPT_TLV( 0x45 , GSM_A_PDU_TYPE_DTAP, DE_NETWORK_NAME , " - Short Name" );

	ELEM_OPT_TV( 0x46 , GSM_A_PDU_TYPE_DTAP, DE_TIME_ZONE , "" );

	ELEM_OPT_TV( 0x47 , GSM_A_PDU_TYPE_DTAP, DE_TIME_ZONE_TIME , "" );

	ELEM_OPT_TLV( 0x48 , GSM_A_PDU_TYPE_DTAP, DE_LSA_ID , "" );

	ELEM_OPT_TLV( 0x49 , GSM_A_PDU_TYPE_DTAP, DE_DAY_SAVING_TIME , "" );

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [7] 9.4.20
 */
static void
dtap_gmm_service_req(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	gsm_a_dtap_pinfo->p2p_dir = P2P_DIR_RECV;

	/* Is included in SRVC TYPE
	ELEM_MAND_V(GSM_A_PDU_TYPE_COMMON, DE_CIPH_KEY_SEQ_NUM );
	curr_offset--;
	curr_len++;
	*/

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_SRVC_TYPE );

	/* P-TMSI Mobile station identity 10.5.1.4 M LV 6 */
	ELEM_MAND_LV(GSM_A_PDU_TYPE_COMMON, DE_MID, "");

	ELEM_OPT_TLV( 0x32 , GSM_A_PDU_TYPE_GM, DE_PDP_CONTEXT_STAT , "" );

	/* MBMS context status 10.5.7.6 TLV 2 - 18 */
	ELEM_OPT_TLV( 0x35 , GSM_A_PDU_TYPE_GM, DE_MBMS_CTX_STATUS , "" );

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [7] 9.4.21
 */
static void
dtap_gmm_service_acc(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	gsm_a_dtap_pinfo->p2p_dir = P2P_DIR_SENT;

	ELEM_OPT_TLV( 0x32 , GSM_A_PDU_TYPE_GM, DE_PDP_CONTEXT_STAT , "" );

	/* MBMS context status 10.5.7.6 TLV 2 - 18 */
	ELEM_OPT_TLV( 0x35 , GSM_A_PDU_TYPE_GM, DE_MBMS_CTX_STATUS , "" );

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [7] 9.4.22
 */
static void
dtap_gmm_service_rej(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	gsm_a_dtap_pinfo->p2p_dir = P2P_DIR_SENT;

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_GMM_CAUSE );

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [8] 9.5.1 Activate PDP context request
 */
static void
dtap_sm_act_pdp_req(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	gsm_a_dtap_pinfo->p2p_dir = P2P_DIR_UNKNOWN;

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_NET_SAPI );

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_LLC_SAPI );

	ELEM_MAND_LV(GSM_A_PDU_TYPE_GM, DE_QOS , " - Requested QoS" );

	ELEM_MAND_LV(GSM_A_PDU_TYPE_GM, DE_PD_PRO_ADDR , " - Requested PDP address" );

	ELEM_OPT_TLV( 0x28 , GSM_A_PDU_TYPE_GM, DE_ACC_POINT_NAME , "" );

	ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT , "" );

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [8] 9.5.2 Activate PDP context accept
 */
static void
dtap_sm_act_pdp_acc(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	gsm_a_dtap_pinfo->p2p_dir = P2P_DIR_UNKNOWN;

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_LLC_SAPI );

	ELEM_MAND_LV(GSM_A_PDU_TYPE_GM, DE_QOS , " - Negotiated QoS" );

#if 0
	/* This is done automatically */
	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_SPARE );
	curr_offset--;
	curr_len++;
#endif

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_RAD_PRIO );

	ELEM_OPT_TLV( 0x2B , GSM_A_PDU_TYPE_GM, DE_PD_PRO_ADDR , "" );

	ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT , "" );

	ELEM_OPT_TLV( 0x34 , GSM_A_PDU_TYPE_GM, DE_PACKET_FLOW_ID , "" );

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [8] 9.5.3 Activate PDP context reject
 */
static void
dtap_sm_act_pdp_rej(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	gsm_a_dtap_pinfo->p2p_dir = P2P_DIR_UNKNOWN;

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_SM_CAUSE );

	ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT , "" );

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [8] 9.5.4 Activate Secondary PDP Context Request
 */
static void
dtap_sm_act_sec_pdp_req(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	gsm_a_dtap_pinfo->p2p_dir = P2P_DIR_UNKNOWN;

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_NET_SAPI );

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_LLC_SAPI );

	ELEM_MAND_LV(GSM_A_PDU_TYPE_GM, DE_QOS , " - Requested QoS" );

	ELEM_MAND_LV(GSM_A_PDU_TYPE_GM, DE_LINKED_TI , "" );

	/* 3GPP TS 24.008 version 6.8.0 Release 6, 36 TFT Traffic Flow Template 10.5.6.12 O TLV 3-257 */
	ELEM_OPT_TLV( 0x36 , GSM_A_PDU_TYPE_GM, DE_TRAFFIC_FLOW_TEMPLATE , "" );

	ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT , "" );

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [7] 9.5.5
 */
static void
dtap_sm_act_sec_pdp_acc(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	gsm_a_dtap_pinfo->p2p_dir = P2P_DIR_UNKNOWN;

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_LLC_SAPI );

	ELEM_MAND_LV(GSM_A_PDU_TYPE_GM, DE_QOS , " - Negotiated QoS" );

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_RAD_PRIO);

#if 0
	/* This is done automatically */
	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_SPARE );
	curr_offset--;
	curr_len++;
#endif

	ELEM_OPT_TLV( 0x34 , GSM_A_PDU_TYPE_GM, DE_PACKET_FLOW_ID , "" );

	ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT , "" );

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [8] 9.5.6 Activate Secondary PDP Context Reject
 */
static void
dtap_sm_act_sec_pdp_rej(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	gsm_a_dtap_pinfo->p2p_dir = P2P_DIR_UNKNOWN;

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_SM_CAUSE );

	ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT , "" );

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [8] 9.5.7 Request PDP context activation
 */
static void
dtap_sm_req_pdp_act(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	gsm_a_dtap_pinfo->p2p_dir = P2P_DIR_UNKNOWN;

	ELEM_MAND_LV(GSM_A_PDU_TYPE_GM, DE_PD_PRO_ADDR , " - Offered PDP address" );

	ELEM_OPT_TLV( 0x28 , GSM_A_PDU_TYPE_GM, DE_ACC_POINT_NAME , "" );

	ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT , "" );

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [8] 9.5.8 Request PDP context activation reject
 */
static void
dtap_sm_req_pdp_act_rej(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	gsm_a_dtap_pinfo->p2p_dir = P2P_DIR_UNKNOWN;

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_SM_CAUSE );

	ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT , "" );

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [8] 9.5.9 Modify PDP context request (Network to MS direction)
 */
static void
dtap_sm_mod_pdp_req_net(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	gsm_a_dtap_pinfo->p2p_dir = P2P_DIR_UNKNOWN;

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM,DE_RAD_PRIO);
#if 0
	/* This is done automatically */
	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_SPARE );
	curr_offset--;
	curr_len++;
#endif

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_LLC_SAPI );

	ELEM_MAND_LV(GSM_A_PDU_TYPE_GM, DE_QOS , " - New QoS" );

	ELEM_OPT_TLV( 0x2B , GSM_A_PDU_TYPE_GM, DE_PD_PRO_ADDR , "" );

	ELEM_OPT_TLV( 0x34 , GSM_A_PDU_TYPE_GM, DE_PACKET_FLOW_ID , "" );

	ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT , "" );

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [8] 9.5.10 Modify PDP context request (MS to network direction)
 */
static void
dtap_sm_mod_pdp_req_ms(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	gsm_a_dtap_pinfo->p2p_dir = P2P_DIR_UNKNOWN;

	ELEM_OPT_TV( 0x32 , GSM_A_PDU_TYPE_GM, DE_LLC_SAPI , " - Requested LLC SAPI" );

	ELEM_OPT_TLV( 0x30 , GSM_A_PDU_TYPE_GM, DE_QOS , " - Requested new QoS" );

	ELEM_OPT_TLV( 0x31 , GSM_A_PDU_TYPE_GM, DE_TRAFFIC_FLOW_TEMPLATE , " - New TFT" );

	ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT , "" );

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [8] 9.5.11 Modify PDP context accept (MS to network direction)
 */
static void
dtap_sm_mod_pdp_acc_ms(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	gsm_a_dtap_pinfo->p2p_dir = P2P_DIR_UNKNOWN;

	ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT , "" );

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [8] 9.5.12 Modify PDP context accept (Network to MS direction)
 */
static void
dtap_sm_mod_pdp_acc_net(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	gsm_a_dtap_pinfo->p2p_dir = P2P_DIR_UNKNOWN;

	ELEM_OPT_TLV( 0x30 , GSM_A_PDU_TYPE_GM, DE_QOS , " - Negotiated QoS" );

	ELEM_OPT_TV( 0x32 , GSM_A_PDU_TYPE_GM, DE_LLC_SAPI , " - Negotiated LLC SAPI" );

	ELEM_OPT_TV_SHORT ( 0x80 , GSM_A_PDU_TYPE_GM , DE_RAD_PRIO , " - New radio priority" );

	ELEM_OPT_TLV( 0x34 , GSM_A_PDU_TYPE_GM, DE_PACKET_FLOW_ID , "" );

	ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT , "" );

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [8] 9.5.13 Modify PDP Context Reject
 */
static void
dtap_sm_mod_pdp_rej(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	gsm_a_dtap_pinfo->p2p_dir = P2P_DIR_UNKNOWN;

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_SM_CAUSE );

	ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT , "" );

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [8] 9.5.14 Deactivate PDP context request
 */
static void
dtap_sm_deact_pdp_req(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	gsm_a_dtap_pinfo->p2p_dir = P2P_DIR_UNKNOWN;

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_SM_CAUSE );

	ELEM_OPT_TV_SHORT( 0x90 , GSM_A_PDU_TYPE_GM , DE_TEAR_DOWN_IND , "" );

	ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT , "" );

	/* MBMS context status 10.5.7.6 TLV 2 - 18 */
	ELEM_OPT_TLV( 0x35 , GSM_A_PDU_TYPE_GM, DE_MBMS_CTX_STATUS , "" );

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [8] 9.5.15 Deactivate PDP context accept
 */
static void
dtap_sm_deact_pdp_acc(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	gsm_a_dtap_pinfo->p2p_dir = P2P_DIR_UNKNOWN;

	ELEM_OPT_TLV( 0x27 , GSM_A_PDU_TYPE_GM, DE_PRO_CONF_OPT , "" );

	/* MBMS context status 10.5.7.6 TLV 2 - 18 */
	ELEM_OPT_TLV( 0x35 , GSM_A_PDU_TYPE_GM, DE_MBMS_CTX_STATUS , "" );

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [8] 9.5.21 SM Status
 */
static void
dtap_sm_status(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	gsm_a_dtap_pinfo->p2p_dir = P2P_DIR_UNKNOWN;

	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_SM_CAUSE );

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [8] 9.5.22 Activate MBMS Context Request
 */

	/* Requested MBMS NSAPI Enhanced Network service access point identifier 10.5.6.15 M V */
	/* Requested LLC SAPI LLC service access point identifier 10.5.6.9 M V 1 */
	/* Supported MBMS bearer capabilities MBMS bearer capabilities 10.5.6.14 M LV 2 - 3 */
	/* Requested multicast address Packet data protocol address 10.5.6.4 M LV 3 - 19 */
	/* Access point name Access point name 10.5.6.1 M LV 2 - 101 */
	/* 35 MBMS protocol configuration options MBMS protocol configuration options 10.5.6.15 O TLV 3 - 253 */

/*
 * [8] 9.5.23 Activate MBMS Context Accept
 */

/*
 * [8] 9.5.24 Activate MBMS Context Reject
 */

/*
 * [8] 9.5.25 Request MBMS Context Activation
 */

/*
 * [8] 9.5.26 Request MBMS Context Activation Reject
 */

#define	NUM_GSM_DTAP_MSG_GMM (sizeof(gsm_a_dtap_msg_gmm_strings)/sizeof(value_string))
static gint ett_gsm_dtap_msg_gmm[NUM_GSM_DTAP_MSG_GMM];
static void (*dtap_msg_gmm_fcn[])(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len) = {
	dtap_gmm_attach_req,		/* Attach Request */
	dtap_gmm_attach_acc,		/* Attach Accept */
	dtap_gmm_attach_com,		/* Attach Complete */
	dtap_gmm_attach_rej,		/* Attach Reject */
	dtap_gmm_detach_req,		/* Detach Request */
	dtap_gmm_detach_acc,		/* Detach Accept */
	dtap_gmm_rau_req,			/* Routing Area Update Request */
	dtap_gmm_rau_acc,			/* Routing Area Update Accept */
	dtap_gmm_rau_com,			/* Routing Area Update Complete */
	dtap_gmm_rau_rej,			/* Routing Area Update Reject */
	dtap_gmm_service_req,		/* Service Request */
	dtap_gmm_service_acc,		/* Service Accept */
	dtap_gmm_service_rej,		/* Service Reject */
	dtap_gmm_ptmsi_realloc_cmd,	/* P-TMSI Reallocation Command */
	dtap_gmm_ptmsi_realloc_com,	/* P-TMSI Reallocation Complete */
	dtap_gmm_auth_ciph_req,		/* Authentication and Ciphering Req */
	dtap_gmm_auth_ciph_resp,	/* Authentication and Ciphering Resp */
	dtap_gmm_auth_ciph_rej,		/* Authentication and Ciphering Rej */
	dtap_gmm_auth_ciph_fail,	/* Authentication and Ciphering Failure */
	dtap_gmm_ident_req,			/* Identity Request */
	dtap_gmm_ident_res,			/* Identity Response */
	dtap_gmm_status,			/* GMM Status */
	dtap_gmm_information,		/* GMM Information */
	NULL,	/* NONE */
};

#define	NUM_GSM_DTAP_MSG_SM (sizeof(gsm_a_dtap_msg_sm_strings)/sizeof(value_string))
static gint ett_gsm_dtap_msg_sm[NUM_GSM_DTAP_MSG_SM];
static void (*dtap_msg_sm_fcn[])(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len) = {
	dtap_sm_act_pdp_req,		/* Activate PDP Context Request */
	dtap_sm_act_pdp_acc,		/* Activate PDP Context Accept */
	dtap_sm_act_pdp_rej,		/* Activate PDP Context Reject */
	dtap_sm_req_pdp_act,		/* Request PDP Context Activation */
	dtap_sm_req_pdp_act_rej,	/* Request PDP Context Activation rej. */
	dtap_sm_deact_pdp_req,		/* Deactivate PDP Context Request */
	dtap_sm_deact_pdp_acc,		/* Deactivate PDP Context Accept */
	dtap_sm_mod_pdp_req_net,	/* Modify PDP Context Request(Network to MS direction) */
	dtap_sm_mod_pdp_acc_ms,		/* Modify PDP Context Accept (MS to network direction) */
	dtap_sm_mod_pdp_req_ms,		/* Modify PDP Context Request(MS to network direction) */
	dtap_sm_mod_pdp_acc_net,	/* Modify PDP Context Accept (Network to MS direction) */
	dtap_sm_mod_pdp_rej,		/* Modify PDP Context Reject */
	dtap_sm_act_sec_pdp_req,	/* Activate Secondary PDP Context Request */
	dtap_sm_act_sec_pdp_acc,	/* Activate Secondary PDP Context Accept */
	dtap_sm_act_sec_pdp_rej,	/* Activate Secondary PDP Context Reject */
	NULL,						/* Reserved: was allocated in earlier phases of the protocol */
	NULL,						/* Reserved: was allocated in earlier phases of the protocol */
	NULL,						/* Reserved: was allocated in earlier phases of the protocol */
	NULL,						/* Reserved: was allocated in earlier phases of the protocol */
	NULL,						/* Reserved: was allocated in earlier phases of the protocol */
	dtap_sm_status,				/* SM Status */
								/* Activate MBMS Context Request */
								/* Activate MBMS Context Accept */
								/* Activate MBMS Context Reject */
								/* Request MBMS Context Activation */
								/* Request MBMS Context Activation Reject */
	NULL,	/* NONE */
};

void get_gmm_msg_params(guint8 oct, const gchar **msg_str, int *ett_tree, int *hf_idx, msg_fcn *msg_fcn)
{
	gint			idx;

	*msg_str = match_strval_idx((guint32) (oct & DTAP_GMM_IEI_MASK), gsm_a_dtap_msg_gmm_strings, &idx);
	*ett_tree = ett_gsm_dtap_msg_gmm[idx];
	*hf_idx = hf_gsm_a_dtap_msg_gmm_type;
	*msg_fcn = dtap_msg_gmm_fcn[idx];

	return;
}

void get_sm_msg_params(guint8 oct, const gchar **msg_str, int *ett_tree, int *hf_idx, msg_fcn *msg_fcn)
{
	gint			idx;

	*msg_str = match_strval_idx((guint32) (oct & DTAP_SM_IEI_MASK), gsm_a_dtap_msg_sm_strings, &idx);
	*ett_tree = ett_gsm_dtap_msg_sm[idx];
	*hf_idx = hf_gsm_a_dtap_msg_sm_type;
	*msg_fcn = dtap_msg_sm_fcn[idx];

	return;
}

/* Register the protocol with Wireshark */
void
proto_register_gsm_a_gm(void)
{
	guint		i;
	guint		last_offset;

	/* Setup list of header fields */

	static hf_register_info hf[] =
	{
	{ &hf_gsm_a_dtap_msg_gmm_type,
		{ "DTAP GPRS Mobility Management Message Type",	"gsm_a.dtap_msg_gmm_type",
		FT_UINT8, BASE_HEX, VALS(gsm_a_dtap_msg_gmm_strings), 0x0,
		"", HFILL }
	},
	{ &hf_gsm_a_dtap_msg_sm_type,
		{ "DTAP GPRS Session Management Message Type",	"gsm_a.dtap_msg_sm_type",
		FT_UINT8, BASE_HEX, VALS(gsm_a_dtap_msg_sm_strings), 0x0,
		"", HFILL }
	},
	{ &hf_gsm_a_gm_elem_id,
		{ "Element ID",	"gsm_a_gm.elem_id",
		FT_UINT8, BASE_DEC, NULL, 0,
		"", HFILL }
	},
	{ &hf_gsm_a_qos_delay_cls,
		{ "Delay class", "gsm_a.qos.delay_cls",
		FT_UINT8, BASE_DEC, VALS(gsm_a_qos_delay_cls_vals), 0x38,
		"Quality of Service Delay Class", HFILL }
	},
	{ &hf_gsm_a_qos_qos_reliability_cls,
		{ "Reliability class", "gsm_a.qos.delay_cls",
		FT_UINT8, BASE_DEC, VALS(gsm_a_qos_delay_cls_vals), 0x07,
		"Reliability class", HFILL }
	},
	{ &hf_gsm_a_qos_traffic_cls,
	  { "Traffic class", "gsm_a.qos.traffic_cls",
		FT_UINT8, BASE_DEC, VALS(gsm_a_qos_traffic_cls_vals), 0xe0,
		"Traffic class", HFILL }
	},
	{ &hf_gsm_a_qos_del_order,
	  { "Delivery order", "gsm_a.qos.del_order",
		FT_UINT8, BASE_DEC, VALS(gsm_a_qos_traffic_cls_vals), 0x18,
		"Delivery order", HFILL }
	},
	{ &hf_gsm_a_qos_del_of_err_sdu,
	  { "Delivery of erroneous SDUs", "gsm_a.qos.del_of_err_sdu",
		FT_UINT8, BASE_DEC, VALS(gsm_a_qos_del_of_err_sdu_vals), 0x03,
		"Delivery of erroneous SDUs", HFILL }
	},
	{ &hf_gsm_a_qos_ber,
	  { "Residual Bit Error Rate (BER)", "gsm_a.qos.ber",
		FT_UINT8, BASE_DEC, VALS(gsm_a_qos_ber_vals), 0xf0,
		"Residual Bit Error Rate (BER)", HFILL }
	},
	{ &hf_gsm_a_qos_sdu_err_rat,
	  { "SDU error ratio", "gsm_a.qos.sdu_err_rat",
		FT_UINT8, BASE_DEC, VALS(gsm_a_qos_sdu_err_rat_vals), 0x0f,
		"SDU error ratio", HFILL }
	},
	{ &hf_gsm_a_qos_traff_hdl_pri,
	  { "Traffic handling priority", "gsm_a.qos.traff_hdl_pri",
		FT_UINT8, BASE_DEC, VALS(gsm_a_qos_traff_hdl_pri_vals), 0x03,
		"Traffic handling priority", HFILL }
	},
	{ &hf_gsm_a_gmm_split_on_ccch,
		{ "SPLIT on CCCH","gsm_a.gmm.split_on_ccch",
		FT_BOOLEAN,8,  TFS(&gsm_a_gmm_split_on_ccch_value), 0x08,
		"SPLIT on CCCH", HFILL }
	},
	{ &hf_gsm_a_gmm_non_drx_timer,
		{ "Non-DRX timer","gsm_a.gmm.non_drx_timer",
		FT_UINT8,BASE_DEC,  VALS(gsm_a_gmm_non_drx_timer_strings), 0x07,
		"Non-DRX timer", HFILL }
	},
	{ &hf_gsm_a_gmm_cn_spec_drs_cycle_len_coef,
		{ "CN Specific DRX cycle length coefficient","gsm_a.gmm.cn_spec_drs_cycle_len_coef",
		FT_UINT8,BASE_DEC,  VALS(gsm_a_gmm_cn_spec_drs_cycle_len_coef_strings), 0xf0,
		"CN Specific DRX cycle length coefficient", HFILL }
	},
	{ &hf_gsm_a_tft_op_code,
		{ "TFT operation code", "gsm_a.tft.op_code",
		FT_UINT8, BASE_DEC, VALS(gsm_a_tft_op_code_vals), 0xe0,
		"TFT operation code", HFILL }
	},
	{ &hf_gsm_a_tft_e_bit,
		{ "E bit","gsm_a.tft.e_bit",
		FT_BOOLEAN,8,  TFS(&gsm_a_tft_e_bit), 0x10,
		"E bit", HFILL }
	},
	{ &hf_gsm_a_tft_pkt_flt,
		{ "Number of packet filters", "gsm_a.tft.pkt_flt",
		FT_UINT8, BASE_DEC, NULL, 0x0f,
		"Number of packet filters", HFILL }
	},
	{ &hf_gsm_a_tft_ip4_address,
		{ "IPv4 adress", "gsm_a.tft.ip4_address", FT_IPv4, BASE_NONE, NULL, 0x0,
		"IPv4 address", HFILL }
	},
	{ &hf_gsm_a_tft_ip4_mask,
		{ "IPv4 address mask", "gsm_a.tft.ip4_mask", FT_IPv4, BASE_NONE, NULL, 0x0,
		"IPv4 address mask", HFILL }},
	{ &hf_gsm_a_tft_ip6_address,
		{ "IPv6 adress", "gsm_a.tft.ip6_address", FT_IPv6, BASE_NONE, NULL, 0x0,
		"IPv6 address", HFILL }
	},
	{ &hf_gsm_a_tft_ip6_mask,
		{ "IPv6 adress mask", "gsm_a.tft.ip6_mask", FT_IPv6, BASE_NONE, NULL, 0x0,
		"IPv6 address mask", HFILL }
	},
	{ &hf_gsm_a_tft_protocol_header,
		{ "Protocol/header", "gsm_a.tft.protocol_header", FT_UINT8, BASE_HEX, NULL, 0x0,
		"Protocol/header", HFILL }
	},
	{ &hf_gsm_a_tft_port,
		{ "Port", "gsm_a.tft.port", FT_UINT16, BASE_DEC, NULL, 0x0,
		"Port", HFILL }
	},
	{ &hf_gsm_a_tft_port_low,
		{ "Low limit port", "gsm_a.tft.port_low", FT_UINT16, BASE_DEC, NULL, 0x0,
		"Low limit port", HFILL }
	},
	{ &hf_gsm_a_tft_port_high,
		{ "High limit port", "gsm_a.tft.port_high", FT_UINT16, BASE_DEC, NULL, 0x0,
		"High limit port", HFILL }
	},
	{ &hf_gsm_a_tft_security,
		{ "IPSec security parameter index", "gsm_a.tft.security", FT_UINT32, BASE_HEX, NULL, 0x0,
		"IPSec security parameter index", HFILL }
	},
	{ &hf_gsm_a_tft_traffic_mask,
		{ "Mask field", "gsm_a.tft.traffic_mask", FT_UINT8, BASE_HEX, NULL, 0x0,
		"Mask field", HFILL }
	},
	{ &hf_gsm_a_ptmsi_sig,
		{ "P-TMSI Signature", "gsm_a.ptmsi_sig", FT_UINT24, BASE_HEX, NULL, 0x0,
		"P-TMSI Signature", HFILL }
	},
	{ &hf_gsm_a_ptmsi_sig2,
		{ "P-TMSI Signature 2", "gsm_a.ptmsi_sig2", FT_UINT24, BASE_HEX, NULL, 0x0,
		"P-TMSI Signature 2", HFILL }
	},
	};

	/* Setup protocol subtree array */
#define	NUM_INDIVIDUAL_ELEMS	15
	static gint *ett[NUM_INDIVIDUAL_ELEMS +
			NUM_GSM_DTAP_MSG_GMM + NUM_GSM_DTAP_MSG_SM +
			NUM_GSM_GM_ELEM];

	ett[0] = &ett_tc_component;
	ett[1] = &ett_tc_invoke_id;
	ett[2] = &ett_tc_linked_id;
	ett[3] = &ett_tc_opr_code;
	ett[4] = &ett_tc_err_code;
	ett[5] = &ett_tc_prob_code;
	ett[6] = &ett_tc_sequence;
	ett[7] = &ett_gmm_drx;
	ett[8] = &ett_gmm_detach_type;
	ett[9] = &ett_gmm_attach_type;
	ett[10] = &ett_gmm_context_stat;
	ett[11] = &ett_gmm_update_type;
	ett[12] = &ett_gmm_radio_cap;
	ett[13] = &ett_gmm_rai;
	ett[14] = &ett_sm_tft;

	last_offset = NUM_INDIVIDUAL_ELEMS;

	for (i=0; i < NUM_GSM_DTAP_MSG_GMM; i++, last_offset++)
	{
		ett_gsm_dtap_msg_gmm[i] = -1;
		ett[last_offset] = &ett_gsm_dtap_msg_gmm[i];
	}

	for (i=0; i < NUM_GSM_DTAP_MSG_SM; i++, last_offset++)
	{
		ett_gsm_dtap_msg_sm[i] = -1;
		ett[last_offset] = &ett_gsm_dtap_msg_sm[i];
	}

	for (i=0; i < NUM_GSM_GM_ELEM; i++, last_offset++)
	{
		ett_gsm_gm_elem[i] = -1;
		ett[last_offset] = &ett_gsm_gm_elem[i];
	}

	proto_a_gm =
		proto_register_protocol("GSM A-I/F GPRS Mobility and Session Management", "GSM Management", "gsm_a_gm");

	proto_register_field_array(proto_a_gm, hf, array_length(hf));

	proto_register_subtree_array(ett, array_length(ett));

	/* subdissector code */
	gprs_sm_pco_subdissector_table = register_dissector_table("sm_pco.protocol",
		"GPRS SM PCO PPP protocol", FT_UINT16, BASE_HEX);
}

void
proto_reg_handoff_gsm_a_gm(void)
{
	data_handle = find_dissector("data");
	rrc_irat_ho_info_handle = find_dissector("rrc.irat.irat_ho_info");
}
