/* packet-gsm_ss.c
 * Routines for GSM Supplementary Services dissection
 *
 * NOTE:
 *	Routines are shared by GSM MAP/GSM A dissectors.
 *	This file provides SHARED routines and is NOT a
 *	standalone dissector.
 *
 * Copyright 2004, Michael Lum <mlum [AT] telostech.com>
 * In association with Telos Technology Inc.
 *
 * Title		3GPP			Other
 *
 *   Reference [1]
 *   Mobile radio Layer 3 supplementary service specification;
 *   Formats and coding
 *   (3GPP TS 24.080 version 4.3.0 Release 4)
 *
 * Michael Lum <mlum [AT] telostech.com>,
 * Created (2004).
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-gsm_map.c (where "WHATEVER_FILE_YOU_USED"
 * is a dissector file; if you just copied this from README.developer,
 * don't bother with the "Copied from" - you don't even need to put
 * in a "Copied from" if you copied an existing dissector, especially
 * if the bulk of the code in the new dissector is your code)
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

#include "epan/packet.h"
#include <epan/tap.h>
#include "asn1.h"

#include "packet-tcap.h"
#include "packet-gsm_sms.h"
#include "packet-gsm_ss.h"


const value_string gsm_ss_err_code_strings[] = {
    { 1,	"Unknown Subscriber" },
    { 3,	"Unknown MSC" },
    { 5,	"Unidentified Subscriber" },
    { 6,	"Absent Subscriber SM" },
    { 7,	"Unknown Equipment" },
    { 8,	"Roaming Not Allowed" },
    { 9,	"Illegal Subscriber" },
    { 10,	"Bearer Service Not Provisioned" },
    { 11,	"Teleservice Not Provisioned" },
    { 12,	"Illegal Equipment" },
    { 13,	"Call Barred" },
    { 14,	"Forwarding Violation" },
    { 15,	"CUG Reject" },
    { 16,	"Illegal SS Operation" },
    { 17,	"SS Error Status" },
    { 18,	"SS Not Available" },
    { 19,	"SS Subscription Violation" },
    { 20,	"SS Incompatibility" },
    { 21,	"Facility Not Supported" },
    { 25,	"No Handover Number Available" },
    { 26,	"Subsequent Handover Failure" },
    { 27,	"Absent Subscriber" },
    { 28,	"Incompatible Terminal" },
    { 29,	"Short Term Denial" },
    { 30,	"Long Term Denial" },
    { 31,	"Subscriber Busy For MT SMS" },
    { 32,	"SM Delivery Failure" },
    { 33,	"Message Waiting List Full" },
    { 34,	"System Failure" },
    { 35,	"Data Missing" },
    { 36,	"Unexpected Data Value" },
    { 37,	"PW Registration Failure" },
    { 38,	"Negative PW Check" },
    { 39,	"No Roaming Number Available" },
    { 40,	"Tracing Buffer Full" },
    { 42,	"Target Cell Outside Group Call Area" },
    { 43,	"Number Of PW Attempts Violation" },
    { 44,	"Number Changed" },
    { 45,	"Busy Subscriber" },
    { 46,	"No Subscriber Reply" },
    { 47,	"Forwarding Failed" },
    { 48,	"OR Not Allowed" },
    { 49,	"ATI Not Allowed" },
    { 50,	"No Group Call Number Available" },
    { 51,	"Resource Limitation" },
    { 52,	"Unauthorized Requesting Network" },
    { 53,	"Unauthorized LCS Client" },
    { 54,	"Position Method Failure" },
    { 58,	"Unknown Or Unreachable LCS Client" },
    { 59,	"MM Event Not Supported" },
    { 60,	"ATSI Not Allowed" },
    { 61,	"ATM Not Allowed" },
    { 62,	"Information Not Available" },
    { 71,	"Unknown Alphabet" },
    { 72,	"USSD Busy" },
    { 120,	"Nbr Sb Exceeded" },
    { 121,	"Rejected By User" },
    { 122,	"Rejected By Network" },
    { 123,	"Deflection To Served Subscriber" },
    { 124,	"Special Service Code" },
    { 125,	"Invalid Deflected To Number" },
    { 126,	"Max Number Of MPTY Participants Exceeded" },
    { 127,	"Resources Not Available" },
    { 0, NULL }
};

const value_string gsm_ss_opr_code_strings[] = {
    { 10,	"Register SS" },
    { 11,	"Erase SS" },
    { 12,	"Activate SS" },
    { 13,	"Deactivate SS" },
    { 14,	"Interrogate SS" },
    { 16,	"Notify SS" },
    { 17,	"Register Password" },
    { 18,	"Get Password" },
    { 19,	"Process Unstructured SS Data" },
    { 38,	"Forward Check SS Indication" },
    { 59,	"Process Unstructured SS Request" },
    { 60,	"Unstructured SS Request" },
    { 61,	"Unstructured SS Notify" },
    { 77,	"Erase CC Entry" },
    { 117,	"Call Deflection" },
    { 118,	"User User Service" },
    { 119,	"Access Register CC Entry" },
    { 120,	"Forward CUG Info" },
    { 121,	"Split MPTY" },
    { 122,	"Retrieve MPTY" },
    { 123,	"Hold MPTY" },
    { 124,	"Build MPTY" },
    { 125,	"Forward Charge Advice" },
    { 126,	"Explicit CT" },
    { 116,	"LCS Location Notification" },
    { 115,	"LCS MOLR" },

    { 0, NULL }
};


/* never initialize in field array */
static int hf_null = -1;
#define	HF_NULL		&hf_null

gint gsm_ss_ett[NUM_GSM_SS_ETT];	/* initialization is left to users */

static gboolean gsm_ss_seven_bit = FALSE;
static gboolean gsm_ss_eight_bit = FALSE;
static gboolean gsm_ss_ucs2 = FALSE;
static gboolean gsm_ss_compressed = FALSE;


typedef struct dgt_set_t
{
    unsigned char out[15];
}
dgt_set_t;

#ifdef MLUM
static dgt_set_t Dgt_tbcd = {
    {
  /*  0   1   2   3   4   5   6   7   8   9   a   b   c   d   e */
     '0','1','2','3','4','5','6','7','8','9','?','B','C','*','#'
    }
};
#endif

static dgt_set_t Dgt_msid = {
    {
  /*  0   1   2   3   4   5   6   7   8   9   a   b   c   d   e */
     '0','1','2','3','4','5','6','7','8','9','?','?','?','?','?'
    }
};


/* FORWARD DECLARATIONS */

static void op_generic_ss(ASN1_SCK *asn1, proto_tree *tree, guint exp_len);


/* GENERIC HELPER FUNCTIONS */

/*
 * Unpack BCD input pattern into output ASCII pattern
 *
 * Input Pattern is supplied using the same format as the digits
 *
 * Returns: length of unpacked pattern
 */
static int
my_dgt_tbcd_unpack(
    char	*out,		/* ASCII pattern out */
    guchar	*in,		/* packed pattern in */
    int		num_octs,	/* Number of octets to unpack */
    dgt_set_t	*dgt		/* Digit definitions */
    )
{
    int cnt = 0;
    unsigned char i;

    while (num_octs)
    {
	/*
	 * unpack first value in byte
	 */
	i = *in++;
	*out++ = dgt->out[i & 0x0f];
	cnt++;

	/*
	 * unpack second value in byte
	 */
	i >>= 4;

	if (i == 0x0f)	/* odd number bytes - hit filler */
	    break;

	*out++ = dgt->out[i];
	cnt++;
	num_octs--;
    }

    *out = '\0';

    return(cnt);
}

static gchar *
my_match_strval(guint32 val, const value_string *vs, gint *idx)
{
    gint	i = 0;

    while (vs[i].strptr) {
	if (vs[i].value == val)
	{
	    *idx = i;
	    return(vs[i].strptr);
	}

	i++;
    }

    *idx = -1;
    return(NULL);
}

/* PARAMETER dissection */

void
param_AddressString(ASN1_SCK *asn1, proto_tree *tree, guint len, int hf_field)
{
    guint	saved_offset;
    gint32	value;
    guchar	*poctets;
    gchar	*str = NULL;
    char	bigbuf[1024];

    saved_offset = asn1->offset;
    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0x80, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, 1,
	"%s :  %sxtension",
	bigbuf, (value & 0x80) ? "No E" : "E");

    switch ((value & 0x70) >> 4)
    {
    case 0x00: str = "unknown"; break;
    case 0x01: str = "International Number"; break;
    case 0x02: str = "National Significant Number"; break;
    case 0x03: str = "Network Specific Number"; break;
    case 0x04: str = "Subscriber Number"; break;
    case 0x05: str = "Reserved"; break;
    case 0x06: str = "Abbreviated Number"; break;
    case 0x07: str = "Reserved for extension"; break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x70, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  %s",
	bigbuf, str);

    switch (value & 0x0f)
    {
    case 0x00: str = "unknown"; break;
    case 0x01: str = "ISDN/Telephony Numbering (Rec ITU-T E.164)"; break;
    case 0x02: str = "spare"; break;
    case 0x03: str = "Data Numbering (ITU-T Rec. X.121)"; break;
    case 0x04: str = "Telex Numbering (ITU-T Rec. F.69)"; break;
    case 0x05: str = "spare"; break;
    case 0x06: str = "Land Mobile Numbering (ITU-T Rec. E.212)"; break;
    case 0x07: str = "spare"; break;
    case 0x08: str = "National Numbering"; break;
    case 0x09: str = "Private Numbering"; break;
    case 0x0f: str = "Reserved for extension"; break;
    default:
	str = "Reserved";
	break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x0f, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, asn1->offset - saved_offset,
	"%s :  %s",
	bigbuf, str);

    saved_offset = asn1->offset;
    asn1_string_value_decode(asn1, len - 1, &poctets);

    my_dgt_tbcd_unpack(bigbuf, poctets, len - 1, &Dgt_msid);
    g_free(poctets);

    if (hf_field == -1)
    {
	proto_tree_add_text(tree, asn1->tvb,
	    saved_offset, len - 1, "BCD Digits %s", bigbuf);
    }
    else
    {
	proto_tree_add_string_format(tree, hf_field, asn1->tvb,
	    saved_offset, len - 1, bigbuf, "BCD Digits %s", bigbuf);
    }
}

static void
param_ssCode(ASN1_SCK *asn1, proto_tree *tree, guint len, int hf_field)
{
    guint	saved_offset;
    gint32	value;
    gchar	*str = NULL;

    hf_field = hf_field;

    saved_offset = asn1->offset;
    asn1_int32_value_decode(asn1, len, &value);

    switch (value)
    {
    case 0x00:
	str = "allSS - all SS";
	break;

    case 0x10:
	str = "allLineIdentificationSS - all line identification SS";
	break;

    case 0x11:
	str = "clip - calling line identification presentation";
	break;

    case 0x12:
	str = "clir - calling line identification restriction";
	break;

    case 0x13:
	str = "colp - connected line identification presentation";
	break;

    case 0x14:
	str = "colr - connected line identification restriction";
	break;

    case 0x15:
	str = "mci - malicious call identification";
	break;

    case 0x18:
	str = "allNameIdentificationSS - all name indentification SS";
	break;

    case 0x19:
	str = "cnap - calling name presentation";
	break;

    case 0x20:
	str = "allForwardingSS - all forwarding SS";
	break;

    case 0x21:
	str = "cfu - call forwarding unconditional";
	break;

    case 0x28:
	str = "allCondForwardingSS - all conditional forwarding SS";
	break;

    case 0x29:
	str = "cfb - call forwarding busy";
	break;

    case 0x2a:
	str = "cfnry - call forwarding on no reply";
	break;

    case 0x2b:
	str = "cfnrc - call forwarding on mobile subscriber not reachable";
	break;

    case 0x24:
	str = "cd - call deflection";
	break;

    case 0x30:
	str = "allCallOfferingSS - all call offering SS includes also all forwarding SS";
	break;

    case 0x31:
	str = "ect - explicit call transfer";
	break;

    case 0x32:
	str = "mah - mobile access hunting";
	break;

    case 0x40:
	str = "allCallCompletionSS - all Call completion SS";
	break;

    case 0x41:
	str = "cw - call waiting";
	break;

    case 0x42:
	str = "hold - call hold";
	break;

    case 0x43:
	str = "ccbs-A - completion of call to busy subscribers, originating side";
	break;

    case 0x44:
	str = "ccbs-B - completion of call to busy subscribers, destination side";
	break;

    case 0x45:
	str = "mc - multicall";
	break;

    case 0x50:
	str = "allMultiPartySS - all multiparty SS";
	break;

    case 0x51:
	str = "multiPTY - multiparty";
	break;

    case 0x60:
	str = "allCommunityOfInterestSS - all community of interest SS";
	break;

    case 0x61:
	str = "cug - closed user group";
	break;

    case 0x70:
	str = "allChargingSS - all charging SS";
	break;

    case 0x71:
	str = "aoci - advice of charge information";
	break;

    case 0x72:
	str = "aocc - advice of charge charging";
	break;

    case 0x80:
	str = "allAdditionalInfoTransferSS - all additional information transfer SS";
	break;

    case 0x81:
	str = "uus1 - UUS1 user-to-user signalling";
	break;

    case 0x82:
	str = "uus2 - UUS2 user-to-user signalling";
	break;

    case 0x83:
	str = "uus3 - UUS3 user-to-user signalling";
	break;

    case 0x90:
	str = "allBarringSS - all barring SS";
	break;

    case 0x91:
	str = "barringOfOutgoingCalls";
	break;

    case 0x92:
	str = "baoc - barring of all outgoing calls";
	break;

    case 0x93:
	str = "boic - barring of outgoing international calls";
	break;

    case 0x94:
	str = "boicExHC - barring of outgoing international calls except those directed to the home PLMN";
	break;

    case 0x99:
	str = "barringOfIncomingCalls";
	break;

    case 0x9a:
	str = "baic - barring of all incoming calls";
	break;

    case 0x9b:
	str = "bicRoam - barring of incoming calls when roaming outside home PLMN Country";
	break;

    case 0xf0:
	str = "allPLMN-specificSS";
	break;

    case 0xa0:
	str = "allCallPrioritySS - all call priority SS";
	break;

    case 0xa1:
	str = "emlpp - enhanced Multilevel Precedence Pre-emption (EMLPP) service";
	break;

    case 0xb0:
	str = "allLCSPrivacyException - all LCS Privacy Exception Classes";
	break;

    case 0xb1:
	str = "universal - allow location by any LCS client";
	break;

    case 0xb2:
	str = "callrelated - allow location by any value added LCS client to which a call is established from the target MS";
	break;

    case 0xb3:
	str = "callunrelated - allow location by designated external value added LCS clients";
	break;

    case 0xb4:
	str = "plmnoperator - allow location by designated PLMN operator LCS clients";
	break;

    case 0xc0:
	str = "allMOLR-SS - all Mobile Originating Location Request Classes";
	break;

    case 0xc1:
	str = "basicSelfLocation - allow an MS to request its own location";
	break;

    case 0xc2:
	str = "autonomousSelfLocation - allow an MS to perform self location without interaction with the PLMN for a predetermined period of time";
	break;

    case 0xc3:
	str = "transferToThirdParty - allow an MS to request transfer of its location to another LCS client";
	break;

    default:
	/*
	 * XXX
	 */
	str = "reserved for future use";
	break;
    }

    proto_tree_add_text(tree, asn1->tvb, saved_offset, len, str);
}

/*
 * See GSM 03.11
 */
static void
param_ssStatus(ASN1_SCK *asn1, proto_tree *tree, guint len, int hf_field)
{
    guint	saved_offset;
    gint32	value;
    char	bigbuf[1024];

    hf_field = hf_field;

    saved_offset = asn1->offset;
    asn1_int32_value_decode(asn1, len, &value);

    other_decode_bitfield_value(bigbuf, value, 0xf0, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, 1,
	"%s :  Unused",
	bigbuf);

    /*
     * Q bit is valid only if A bit is "Active"
     */
    other_decode_bitfield_value(bigbuf, value, 0x08, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, 1,
	"%s :  Q bit: %s",
	bigbuf,
	(value & 0x01) ?
	    ((value & 0x08) ? "Quiescent" : "Operative") : "N/A");

    other_decode_bitfield_value(bigbuf, value, 0x04, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, 1,
	"%s :  P bit: %sProvisioned",
	bigbuf,
	(value & 0x04) ? "" : "Not ");

    other_decode_bitfield_value(bigbuf, value, 0x02, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, 1,
	"%s :  R bit: %sRegistered",
	bigbuf,
	(value & 0x02) ? "" : "Not ");

    other_decode_bitfield_value(bigbuf, value, 0x01, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, 1,
	"%s :  A bit: %sActive",
	bigbuf,
	(value & 0x01) ? "" : "Not ");
}

static void
param_bearerservice(ASN1_SCK *asn1, proto_tree *tree, guint len, int hf_field)
{
    guint	saved_offset;
    gint32	value;
    gchar	*str = NULL;

    hf_field = hf_field;

    saved_offset = asn1->offset;
    asn1_int32_value_decode(asn1, len, &value);

    switch (value)
    {
    case 0x00: str = "allBearerServices"; break;
    case 0x10: str = "allDataCDA-Services"; break;
    case 0x11: str = "dataCDA-300bps"; break;
    case 0x12: str = "dataCDA-1200bps"; break;
    case 0x13: str = "dataCDA-1200-75bps"; break;
    case 0x14: str = "dataCDA-2400bps"; break;
    case 0x15: str = "dataCDA-4800bps"; break;
    case 0x16: str = "dataCDA-9600bps"; break;
    case 0x17: str = "general-dataCDA"; break;
    case 0x18: str = "allDataCDS-Services"; break;
    case 0x1a: str = "dataCDS-1200bps"; break;
    case 0x1c: str = "dataCDS-2400bps"; break;
    case 0x1d: str = "dataCDS-4800bps"; break;
    case 0x1e: str = "dataCDS-9600bps"; break;
    case 0x1f: str = "general-dataCDS"; break;

    case 0x20: str = "allPadAccessCA-Services"; break;
    case 0x21: str = "padAccessCA-300bps"; break;
    case 0x22: str = "padAccessCA-1200bps"; break;
    case 0x23: str = "padAccessCA-1200-75bps"; break;
    case 0x24: str = "padAccessCA-2400bps"; break;
    case 0x25: str = "padAccessCA-4800bps"; break;
    case 0x26: str = "padAccessCA-9600bps"; break;
    case 0x27: str = "general-padAccessCA"; break;
    case 0x28: str = "allDataPDS-Services"; break;
    case 0x2c: str = "dataPDS-2400bps"; break;
    case 0x2d: str = "dataPDS-4800bps"; break;
    case 0x2e: str = "dataPDS-9600bps"; break;
    case 0x2f: str = "general-dataPDS"; break;

    case 0x30: str = "allAlternateSpeech-DataCDA"; break;
    case 0x38: str = "allAlternateSpeech-DataCDS"; break;
    case 0x40: str = "allSpeechFollowedByDataCDA"; break;
    case 0x48: str = "allSpeechFollowedByDataCDS"; break;

    case 0x50: str = "allDataCircuitAsynchronous"; break;
    case 0x60: str = "allAsynchronousServices"; break;
    case 0x58: str = "allDataCircuitSynchronous"; break;
    case 0x68: str = "allSynchronousServices"; break;

    case 0xd0: str = "allPLMN-specificBS"; break;
    case 0xd1: str = "plmn-specificBS-1"; break;
    case 0xd2: str = "plmn-specificBS-2"; break;
    case 0xd3: str = "plmn-specificBS-3"; break;
    case 0xd4: str = "plmn-specificBS-4"; break;
    case 0xd5: str = "plmn-specificBS-5"; break;
    case 0xd6: str = "plmn-specificBS-6"; break;
    case 0xd7: str = "plmn-specificBS-7"; break;
    case 0xd8: str = "plmn-specificBS-8"; break;
    case 0xd9: str = "plmn-specificBS-9"; break;
    case 0xda: str = "plmn-specificBS-A"; break;
    case 0xdb: str = "plmn-specificBS-B"; break;
    case 0xdc: str = "plmn-specificBS-C"; break;
    case 0xdd: str = "plmn-specificBS-D"; break;
    case 0xde: str = "plmn-specificBS-E"; break;
    case 0xdf: str = "plmn-specificBS-F"; break;

    default:
	str = "Undefined";
	break;
    }

    proto_tree_add_text(tree, asn1->tvb, saved_offset, len, str);
}

static void
param_teleservice(ASN1_SCK *asn1, proto_tree *tree, guint len, int hf_field)
{
    guint	saved_offset;
    gint32	value;
    gchar	*str = NULL;

    hf_field = hf_field;

    saved_offset = asn1->offset;
    asn1_int32_value_decode(asn1, len, &value);

    switch (value)
    {
    case 0x00: str = "allTeleservices"; break;
    case 0x10: str = "allSpeechTransmissionServices"; break;
    case 0x11: str = "telephony"; break;
    case 0x12: str = "emergencyCalls"; break;
    case 0x20: str = "allShortMessageServices"; break;
    case 0x21: str = "shortMessageMT-PP"; break;
    case 0x22: str = "shortMessageMO-PP"; break;
    case 0x60: str = "allFacsimileTransmissionServices"; break;
    case 0x61: str = "facsimileGroup3AndAlterSpeech"; break;
    case 0x62: str = "automaticFacsimileGroup3"; break;
    case 0x63: str = "facsimileGroup4"; break;

    case 0x70: str = "allDataTeleservices"; break;
    case 0x80: str = "allTeleservices-ExeptSMS"; break;

    case 0x90: str = "allVoiceGroupCallServices"; break;
    case 0x91: str = "voiceGroupCall"; break;
    case 0x92: str = "voiceBroadcastCall"; break;

    case 0xd0: str = "allPLMN-specificTS"; break;
    case 0xd1: str = "plmn-specificTS-1"; break;
    case 0xd2: str = "plmn-specificTS-2"; break;
    case 0xd3: str = "plmn-specificTS-3"; break;
    case 0xd4: str = "plmn-specificTS-4"; break;
    case 0xd5: str = "plmn-specificTS-5"; break;
    case 0xd6: str = "plmn-specificTS-6"; break;
    case 0xd7: str = "plmn-specificTS-7"; break;
    case 0xd8: str = "plmn-specificTS-8"; break;
    case 0xd9: str = "plmn-specificTS-9"; break;
    case 0xda: str = "plmn-specificTS-A"; break;
    case 0xdb: str = "plmn-specificTS-B"; break;
    case 0xdc: str = "plmn-specificTS-C"; break;
    case 0xdd: str = "plmn-specificTS-D"; break;
    case 0xde: str = "plmn-specificTS-E"; break;
    case 0xdf: str = "plmn-specificTS-F"; break;

    default:
	str = "Undefined";
	break;
    }

    proto_tree_add_text(tree, asn1->tvb, saved_offset, len, str);
}

/*
 * GSM 03.38
 * Same as Cell Broadcast
 */
static void
param_ussdDCS(ASN1_SCK *asn1, proto_tree *tree, guint len, int hf_field)
{
    guint		saved_offset;
    gint32		value;
    gchar		*str = NULL;
    char		bigbuf[1024];
    proto_tree		*subtree;
    proto_item		*item;

    hf_field = hf_field;

    gsm_ss_seven_bit = FALSE;
    gsm_ss_eight_bit = FALSE;
    gsm_ss_ucs2 = FALSE;
    gsm_ss_compressed = FALSE;

    saved_offset = asn1->offset;
    asn1_int32_value_decode(asn1, len, &value);

    item =
	proto_tree_add_text(tree, asn1->tvb,
	    saved_offset, len,
	    "Data Coding Scheme (%d)",
	    value);

    subtree = proto_item_add_subtree(item, gsm_ss_ett[GSM_SS_ETT_PARAM]);

    if ((value & 0xf0) == 0x00)
    {
	/* 0000....  Language using the default alphabet */

	switch (value & 0x0f)
	{
	case 0x00: str = "German"; break;
	case 0x01: str = "English"; break;
	case 0x02: str = "Italian"; break;
	case 0x03: str = "French"; break;
	case 0x04: str = "Spanish"; break;
	case 0x05: str = "Dutch"; break;
	case 0x06: str = "Swedish"; break;
	case 0x07: str = "Danish"; break;
	case 0x08: str = "Portuguese"; break;
	case 0x09: str = "Finnish"; break;
	case 0x0a: str = "Norwegian"; break;
	case 0x0b: str = "Greek"; break;
	case 0x0c: str = "Turkish"; break;
	case 0x0d: str = "Hungarian"; break;
	case 0x0e: str = "Polish"; break;
	case 0x0f: str = "Language unspecified"; break;
	}

	other_decode_bitfield_value(bigbuf, value, 0x0f, 8);
	proto_tree_add_text(subtree, asn1->tvb,
	    saved_offset, 1,
	    "%s :  %s language using default alphabet",
	    bigbuf,
	    str);

	gsm_ss_seven_bit = TRUE;
    }
    else if ((value & 0xf0) == 0x10)
    {
	switch (value & 0x0f)
	{
	case 0x00: str = "Default alphabet; message preceded by language indication"; break;
	case 0x01: str = "UCS2; message preceded by language indication"; break;
	default:
	    str = "Reserved for European languages";
	    break;
	}

	other_decode_bitfield_value(bigbuf, value, 0xff, 8);
	proto_tree_add_text(subtree, asn1->tvb,
	    saved_offset, 1,
	    "%s :  %s",
	    bigbuf,
	    str);
    }
    else if ((value & 0xf0) == 0x20)
    {
	switch (value & 0x0f)
	{
	case 0x00: str = "Czech"; break;
	default:
	    str = "Reserved for European languages using the default alphabet";
	    break;
	}

	other_decode_bitfield_value(bigbuf, value, 0xff, 8);
	proto_tree_add_text(subtree, asn1->tvb,
	    saved_offset, 1,
	    "%s :  %s",
	    bigbuf,
	    str);
    }
    else if ((value & 0xf0) == 0x30)
    {
	other_decode_bitfield_value(bigbuf, value, 0xff, 8);
	proto_tree_add_text(subtree, asn1->tvb,
	    saved_offset, 1,
	    "%s :  Reserved for European Languages using the default alphabet",
	    bigbuf);
    }
    else if ((value & 0xc0) == 0x40)
    {
	other_decode_bitfield_value(bigbuf, value, 0xc0, 8);
	proto_tree_add_text(subtree, asn1->tvb,
	    saved_offset, 1,
	    "%s :  General Data Coding indication",
	    bigbuf);

	gsm_ss_compressed = (value & 0x20) >> 5;

	other_decode_bitfield_value(bigbuf, value, 0x20, 8);
	proto_tree_add_text(subtree, asn1->tvb,
	    saved_offset, 1,
	    "%s :  Text is %scompressed",
	    bigbuf,
	    gsm_ss_compressed ? "" : "not ");

	other_decode_bitfield_value(bigbuf, value, 0x10, 8);
	proto_tree_add_text(subtree, asn1->tvb,
	    saved_offset, 1,
	    "%s :  %s",
	    bigbuf,
	    (value & 0x10) ? "Message class is defined below" :
		"Reserved, no message class");

	switch ((value & 0x0c) >> 2)
	{
	case 0x00: str = "GSM 7 bit default alphabet";
	    gsm_ss_seven_bit = TRUE;
	    break;
	case 0x01: str = "8 bit data"; break;
	case 0x02: str = "UCS2 (16 bit)";
	    gsm_ss_ucs2 = TRUE;
	    break;
	case 0x03: str = "Reserved"; break;
	}

	other_decode_bitfield_value(bigbuf, value, 0x0c, 8);
	proto_tree_add_text(subtree, asn1->tvb,
	    saved_offset, 1,
	    "%s :  Character set: %s",
	    bigbuf,
	    str);

	switch (value & 0x03)
	{
	case 0x00: str = "Class 0"; break;
	case 0x01: str = "Class 1 Default meaning: ME-specific"; break;
	case 0x02: str = "Class 2 (U)SIM specific message"; break;
	case 0x03: str = "Class 3 Default meaning: TE-specific"; break;
	}

	other_decode_bitfield_value(bigbuf, value, 0x03, 8);
	proto_tree_add_text(subtree, asn1->tvb,
	    saved_offset, 1,
	    "%s :  Message Class: %s%s",
	    bigbuf,
	    str,
	    (value & 0x10) ? "" : " (reserved)");
    }
    else if ((value & 0xf0) == 0xf0)
    {
	other_decode_bitfield_value(bigbuf, value, 0xf0, 8);
	proto_tree_add_text(subtree, asn1->tvb,
	    saved_offset, 1,
	    "%s :  Data Coding / Message Handling",
	    bigbuf);

	other_decode_bitfield_value(bigbuf, value, 0x08, 8);
	proto_tree_add_text(subtree, asn1->tvb,
	    saved_offset, 1,
	    "%s :  Reserved",
	    bigbuf);

	gsm_ss_seven_bit = !(gsm_ss_eight_bit = (value & 0x04) ? TRUE : FALSE);

	other_decode_bitfield_value(bigbuf, value, 0x04, 8);
	proto_tree_add_text(subtree, asn1->tvb,
	    saved_offset, 1,
	    "%s :  Message coding: %s",
	    bigbuf,
	    gsm_ss_eight_bit ? "8 bit data" : "Default alphabet");

	switch (value & 0x03)
	{
	case 0x00: str = "No message class"; break;
	case 0x01: str = "Class 1 user defined"; break;
	case 0x02: str = "Class 2 user defined"; break;
	case 0x03: str = "Class 3 Default meaning: TE-specific"; break;
	}

	other_decode_bitfield_value(bigbuf, value, 0x03, 8);
	proto_tree_add_text(subtree, asn1->tvb,
	    saved_offset, 1,
	    "%s :  Message Class: %s",
	    bigbuf,
	    str);
    }
    else
    {
	other_decode_bitfield_value(bigbuf, value, 0xff, 8);
	proto_tree_add_text(subtree, asn1->tvb,
	    saved_offset, 1,
	    "%s :  Reserved coding groups",
	    bigbuf);
    }
}

static void
param_ussdString(ASN1_SCK *asn1, proto_tree *tree, guint len, int hf_field)
{
    guint		saved_offset;
    char		bigbuf[1024];
    guint8		fill_bits;
    guint32		out_len;
    char		*ustr;

    hf_field = hf_field;

    saved_offset = asn1->offset;

    if (gsm_ss_compressed)
    {
	proto_tree_add_text(tree, asn1->tvb,
	    saved_offset, len,
	    "Compressed data");
    }
    else
    {
	if (gsm_ss_seven_bit)
	{
	    fill_bits = 0;

	    out_len =
		gsm_sms_char_7bit_unpack(fill_bits, len, sizeof(bigbuf),
		    tvb_get_ptr(asn1->tvb, saved_offset, len), bigbuf);
	    bigbuf[out_len] = '\0';
	    gsm_sms_char_ascii_decode(bigbuf, bigbuf, out_len);

	    proto_tree_add_text(tree, asn1->tvb, saved_offset, len, "%s", bigbuf);
	}
	else if (gsm_ss_eight_bit)
	{
	    proto_tree_add_text(tree, asn1->tvb, saved_offset, len, "%s",
	        tvb_format_text(asn1->tvb, saved_offset, len));
	}
	else if (gsm_ss_ucs2)
	{
	    ustr = tvb_fake_unicode(asn1->tvb, saved_offset, len, FALSE);
	    proto_tree_add_text(tree, asn1->tvb, saved_offset, len, "%s", ustr);
	    g_free(ustr);
	}
	else
	{
	    /* don't know what form it is */

	    proto_tree_add_text(tree, asn1->tvb,
		saved_offset, len,
		"Parameter Data");
	}
    }

    asn1->offset += len;
}

static void
param_ia5String(ASN1_SCK *asn1, proto_tree *tree, guint len, int hf_field)
{
    guint		saved_offset;

    hf_field = hf_field;

    saved_offset = asn1->offset;

    proto_tree_add_text(tree, asn1->tvb, saved_offset, len, "%s",
	tvb_format_text(asn1->tvb, saved_offset, len));

    asn1->offset += len;
}

static void
param_password(ASN1_SCK *asn1, proto_tree *tree, guint len, int hf_field)
{
    guint		saved_offset;

    hf_field = hf_field;

    saved_offset = asn1->offset;

    proto_tree_add_text(tree, asn1->tvb, saved_offset, len, "%s",
	tvb_format_text(asn1->tvb, saved_offset, len));

    asn1->offset += len;
}

static void
param_guidanceInfo(ASN1_SCK *asn1, proto_tree *tree, guint len, int hf_field)
{
    guint		saved_offset;
    gint32		value;
    gchar		*str = NULL;

    hf_field = hf_field;

    saved_offset = asn1->offset;
    asn1_int32_value_decode(asn1, 1, &value);

    switch (value)
    {
    case 0: str = "enterPW"; break;
    case 1: str = "enterNewPW"; break;
    case 2: str = "enterNewPW-Again"; break;
    default:
	str = "Unknown";
	break;
    }

    proto_tree_add_text(tree, asn1->tvb, saved_offset, len, str);
}

static void
param_forwardingOpt(ASN1_SCK *asn1, proto_tree *tree, guint len, int hf_field)
{
    guint		saved_offset;
    gint32		value;
    char		bigbuf[1024];
    gchar		*str = NULL;

    hf_field = hf_field;

    saved_offset = asn1->offset;
    asn1_int32_value_decode(asn1, 1, &value);

    other_decode_bitfield_value(bigbuf, value, 0x80, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, 1,
	"%s :  %snotification to forwarding party",
	bigbuf,
	(value & 0x80) ? "" : "no ");

    other_decode_bitfield_value(bigbuf, value, 0x40, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, 1,
	"%s :  %sredirecting presentation",
	bigbuf,
	(value & 0x40) ? "" : "no ");

    other_decode_bitfield_value(bigbuf, value, 0x20, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, 1,
	"%s :  %snotification to calling party",
	bigbuf,
	(value & 0x20) ? "" : "no ");

    other_decode_bitfield_value(bigbuf, value, 0x10, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, 1,
	"%s :  unused",
	bigbuf);

    switch ((value & 0x0c) >> 2)
    {
    case 0x00: str = "MS not reachable"; break;
    case 0x01: str = "MS busy"; break;
    case 0x02: str = "No reply"; break;
    case 0x03: str = "Unconditional (in SRI result) or Deflection"; break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x0c, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, 1,
	"%s :  forwarding reason, %s (%u)",
	bigbuf,
	str,
	(value & 0x0c) >> 2);

    other_decode_bitfield_value(bigbuf, value, 0x03, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, 1,
	"%s :  unused",
	bigbuf);

    asn1->offset += len;
}


typedef enum
{
    GSM_SS_P_SS_CODE,			/* SS-Code */
    GSM_SS_P_SS_STATUS,			/* SS-Status */
    GSM_SS_P_BEARERSERVICE,		/* Bearer Service */
    GSM_SS_P_TELESERVICE,		/* Tele Service */
    GSM_SS_P_FORWARD_TO_NUM,		/* Forward to Number */
    GSM_SS_P_LONG_FORWARD_TO_NUM,	/* Long Forward to Number */
    GSM_SS_P_USSD_DCS,			/* USSD Data Coding Scheme */
    GSM_SS_P_USSD_STRING,		/* USSD String */
    GSM_SS_P_IA5_STRING,		/* IA5 String */
    GSM_SS_P_PASSWORD,			/* Password */
    GSM_SS_P_GUIDANCE_INFO,		/* Guidance Info */
    GSM_SS_P_FORWARDING_OPT,		/* Forwarding Options */
    GSM_SS_P_NONE			/* NONE */
}
param_idx_t;

#define	NUM_PARAM_1 (GSM_SS_P_NONE+1)
static gint ett_param_1[NUM_PARAM_1];
static void (*param_1_fcn[])(ASN1_SCK *asn1, proto_tree *tree, guint len, int hf_field) = {
    param_ssCode,			/* SS-Code */
    param_ssStatus,			/* SS-Status */
    param_bearerservice,		/* Bearer Service */
    param_teleservice,			/* Tele Service */
    param_AddressString,		/* Forward to Number */
    param_AddressString,		/* Long Forward to Number */
    param_ussdDCS,			/* USSD Data Coding Scheme */
    param_ussdString,			/* USSD String */
    param_ia5String,			/* IA5 String */
    param_password,			/* Password */
    param_guidanceInfo,			/* Guidance Info */
    param_forwardingOpt,		/* Forwarding Options */
    NULL				/* NONE */
};

static int *param_1_hf[] = {
    HF_NULL,				/* SS-Code */
    HF_NULL,				/* SS-Status */
    HF_NULL,				/* Bearer Service */
    HF_NULL,				/* Tele Service */
    HF_NULL,				/* Forward to Number */
    HF_NULL,				/* Long Forward to Number */
    HF_NULL,				/* USSD Data Coding Scheme */
    HF_NULL,				/* USSD String */
    HF_NULL,				/* IA5 String */
    HF_NULL,				/* Password */
    HF_NULL,				/* Guidance Info */
    HF_NULL,				/* Forwarding Options */
    NULL				/* NONE */
};

#define	GSM_SS_START_SUBTREE(_Gtree, _Gsaved_offset, _Gtag, _Gstr1, _Gett, _Gdef_len_p, _Glen_p, _Gsubtree_p) \
    { \
	guint		_len_offset; \
	proto_item	*_item; \
 \
	_len_offset = asn1->offset; \
	asn1_length_decode(asn1, _Gdef_len_p, _Glen_p); \
 \
	_item = \
	    proto_tree_add_text(_Gtree, asn1->tvb, _Gsaved_offset, -1, _Gstr1); \
 \
	_Gsubtree_p = proto_item_add_subtree(_item, _Gett); \
 \
	proto_tree_add_text(_Gsubtree_p, asn1->tvb, \
	    _Gsaved_offset, _len_offset - _Gsaved_offset, "Tag: 0x%02x", _Gtag); \
 \
	if (*_Gdef_len_p) \
	{ \
	    proto_tree_add_text(_Gsubtree_p, asn1->tvb, \
		_len_offset, asn1->offset - _len_offset, "Length: %d", *_Glen_p); \
	} \
	else \
	{ \
	    proto_tree_add_text(_Gsubtree_p, asn1->tvb, \
		_len_offset, asn1->offset - _len_offset, "Length: Indefinite"); \
 \
	    *_Glen_p = tcap_find_eoc(asn1); \
	} \
 \
	proto_item_set_len(_item, (asn1->offset - _Gsaved_offset) + *_Glen_p + \
	    (*_Gdef_len_p ? 0 : TCAP_EOC_LEN)); \
    }

#define	GSM_SS_PARAM_DISPLAY(Gtree, Goffset, Gtag, Ga1, Ga2) \
    { \
	gint		_ett_param_idx; \
	guint		_len; \
	void		(*_param_fcn)(ASN1_SCK *asn1, proto_tree *tree, guint len, int hf_field) = NULL; \
	int		*_param_hf = NULL; \
	proto_tree	*_subtree; \
	gboolean	_def_len; \
 \
	if (Ga1 == GSM_SS_P_NONE) \
	{ \
	    _ett_param_idx = gsm_ss_ett[GSM_SS_ETT_PARAM]; \
	    _param_fcn = NULL; \
	    _param_hf = HF_NULL; \
	} \
	else \
	{ \
	    _ett_param_idx = ett_param_1[Ga1]; \
	    _param_fcn = param_1_fcn[Ga1]; \
	    _param_hf = param_1_hf[Ga1]; \
	} \
 \
	GSM_SS_START_SUBTREE(Gtree, Goffset, Gtag, Ga2, _ett_param_idx, &_def_len, &_len, _subtree); \
 \
	if (_len > 0) \
	{ \
	    if (Ga1 == GSM_SS_P_NONE || _param_fcn == NULL) \
	    { \
		proto_tree_add_text(_subtree, asn1->tvb, \
		    asn1->offset, _len, "Parameter Data"); \
 \
		asn1->offset += _len; \
	    } \
	    else \
	    { \
		(*_param_fcn)(asn1, _subtree, _len, *_param_hf); \
	    } \
	} \
 \
	if (!_def_len) \
	{ \
	    guint	_saved_offset; \
 \
	    _saved_offset = asn1->offset; \
	    asn1_eoc_decode(asn1, -1); \
 \
	    proto_tree_add_text(Gtree, asn1->tvb, \
		_saved_offset, asn1->offset - _saved_offset, "End of Contents"); \
	} \
    }


static void
param_forwardingFeature(ASN1_SCK *asn1, proto_tree *tree, guint exp_len)
{
    guint		saved_offset;
    guint		tag, len;
    gboolean		def_len;
    proto_tree		*subtree;

    exp_len = exp_len;

    saved_offset = asn1->offset;
    asn1_id_decode1(asn1, &tag);

    GSM_SS_START_SUBTREE(tree, saved_offset, tag, "Forwarding Feature",
	gsm_ss_ett[GSM_SS_ETT_SEQUENCE],
	&def_len, &len, subtree);

    if (tcap_check_tag(asn1, 0x82))
    {
	saved_offset = asn1->offset;
	asn1_id_decode1(asn1, &tag);

	GSM_SS_PARAM_DISPLAY(subtree, saved_offset, tag, GSM_SS_P_BEARERSERVICE, "Bearerservice");
    }

    if (tcap_check_tag(asn1, 0x83))
    {
	saved_offset = asn1->offset;
	asn1_id_decode1(asn1, &tag);

	GSM_SS_PARAM_DISPLAY(subtree, saved_offset, tag, GSM_SS_P_TELESERVICE, "Teleservice");
    }

    if (tcap_check_tag(asn1, 0x84))
    {
	saved_offset = asn1->offset;
	asn1_id_decode1(asn1, &tag);

	GSM_SS_PARAM_DISPLAY(subtree, saved_offset, tag, GSM_SS_P_SS_STATUS, "SS-Status");
    }

    if (tcap_check_tag(asn1, 0x85))
    {
	saved_offset = asn1->offset;
	asn1_id_decode1(asn1, &tag);

	GSM_SS_PARAM_DISPLAY(subtree, saved_offset, tag, GSM_SS_P_FORWARD_TO_NUM, "Forwarded to Number");
    }

    if (tcap_check_tag(asn1, 0x88))
    {
	saved_offset = asn1->offset;
	asn1_id_decode1(asn1, &tag);

	GSM_SS_PARAM_DISPLAY(subtree, saved_offset, tag, GSM_SS_P_NONE, "Forwarded to Subaddress");
    }

    if (tcap_check_tag(asn1, 0x86))
    {
	saved_offset = asn1->offset;
	asn1_id_decode1(asn1, &tag);

	GSM_SS_PARAM_DISPLAY(subtree, saved_offset, tag, GSM_SS_P_FORWARDING_OPT, "Forwarding Options");
    }

    if (tcap_check_tag(asn1, 0x87))
    {
	saved_offset = asn1->offset;
	asn1_id_decode1(asn1, &tag);

	GSM_SS_PARAM_DISPLAY(subtree, saved_offset, tag, GSM_SS_P_NONE, "No Reply Condition Time");
    }

    if (tcap_check_tag(asn1, 0x89))
    {
	saved_offset = asn1->offset;
	asn1_id_decode1(asn1, &tag);

	GSM_SS_PARAM_DISPLAY(subtree, saved_offset, tag, GSM_SS_P_LONG_FORWARD_TO_NUM, "Long Forward to Number");
    }

    if (!def_len)
    {
	saved_offset = asn1->offset;
	asn1_eoc_decode(asn1, -1);

	proto_tree_add_text(subtree, asn1->tvb,
	    saved_offset, asn1->offset - saved_offset, "End of Contents");
    }
}

static void
param_forwardingFeatureList(ASN1_SCK *asn1, proto_tree *tree, guint exp_len)
{
    guint		saved_offset, start_offset;
    guint		tag, len;
    gboolean		def_len;
    proto_tree		*subtree;

    saved_offset = asn1->offset;
    asn1_id_decode1(asn1, &tag);

    GSM_SS_START_SUBTREE(tree, saved_offset, tag, "Forwarding Feature List",
	gsm_ss_ett[GSM_SS_ETT_SEQUENCE],
	&def_len, &len, subtree);

    start_offset = asn1->offset;

    while ((tvb_length_remaining(asn1->tvb, asn1->offset) > 0) &&
	(!tcap_check_tag(asn1, 0)))
    {
	if ((exp_len != 0) &&
	    ((asn1->offset - saved_offset) >= exp_len))
	{
	    break;
	}

	param_forwardingFeature(asn1, subtree, len - (asn1->offset - start_offset));
    }

    if (!def_len)
    {
	saved_offset = asn1->offset;
	asn1_eoc_decode(asn1, -1);

	proto_tree_add_text(subtree, asn1->tvb,
	    saved_offset, asn1->offset - saved_offset, "End of Contents");
    }
}

static void
param_callBarringFeature(ASN1_SCK *asn1, proto_tree *tree, guint exp_len)
{
    guint		saved_offset;
    guint		tag, len;
    gboolean		def_len;
    proto_tree		*subtree;

    exp_len = exp_len;

    saved_offset = asn1->offset;
    asn1_id_decode1(asn1, &tag);

    GSM_SS_START_SUBTREE(tree, saved_offset, tag, "Call Barring Feature",
	gsm_ss_ett[GSM_SS_ETT_SEQUENCE],
	&def_len, &len, subtree);

    if (tcap_check_tag(asn1, 0x82))
    {
	saved_offset = asn1->offset;
	asn1_id_decode1(asn1, &tag);

	GSM_SS_PARAM_DISPLAY(subtree, saved_offset, tag, GSM_SS_P_BEARERSERVICE, "Bearerservice");
    }

    if (tcap_check_tag(asn1, 0x83))
    {
	saved_offset = asn1->offset;
	asn1_id_decode1(asn1, &tag);

	GSM_SS_PARAM_DISPLAY(subtree, saved_offset, tag, GSM_SS_P_TELESERVICE, "Teleservice");
    }

    if (tcap_check_tag(asn1, 0x84))
    {
	saved_offset = asn1->offset;
	asn1_id_decode1(asn1, &tag);

	GSM_SS_PARAM_DISPLAY(subtree, saved_offset, tag, GSM_SS_P_SS_STATUS, "SS-Status");
    }

    if (!def_len)
    {
	saved_offset = asn1->offset;
	asn1_eoc_decode(asn1, -1);

	proto_tree_add_text(subtree, asn1->tvb,
	    saved_offset, asn1->offset - saved_offset, "End of Contents");
    }
}

static void
param_callBarringFeatureList(ASN1_SCK *asn1, proto_tree *tree, guint exp_len)
{
    guint		saved_offset, start_offset;
    guint		tag, len;
    gboolean		def_len;
    proto_tree		*subtree;

    saved_offset = asn1->offset;
    asn1_id_decode1(asn1, &tag);

    GSM_SS_START_SUBTREE(tree, saved_offset, tag, "Call Barring Feature List",
	gsm_ss_ett[GSM_SS_ETT_SEQUENCE],
	&def_len, &len, subtree);

    start_offset = asn1->offset;

    while ((tvb_length_remaining(asn1->tvb, asn1->offset) > 0) &&
	(!tcap_check_tag(asn1, 0)))
    {
	if ((exp_len != 0) &&
	    ((asn1->offset - saved_offset) >= exp_len))
	{
	    break;
	}

	param_callBarringFeature(asn1, subtree, len - (asn1->offset - start_offset));
    }

    if (!def_len)
    {
	saved_offset = asn1->offset;
	asn1_eoc_decode(asn1, -1);

	proto_tree_add_text(subtree, asn1->tvb,
	    saved_offset, asn1->offset - saved_offset, "End of Contents");
    }
}

static void
param_ssData(ASN1_SCK *asn1, proto_tree *tree, guint exp_len)
{
    guint		saved_offset;

    saved_offset = asn1->offset;

    /* XXX */
    op_generic_ss(asn1, tree, exp_len);
}

static void
param_ssInfo(ASN1_SCK *asn1, proto_tree *tree)
{
    guint		saved_offset, start_offset;
    guint		tag, len;
    gboolean		def_len = FALSE;
    proto_tree		*subtree;

    saved_offset = asn1->offset;
    asn1_id_decode1(asn1, &tag);

    switch (tag)
    {
    case 0xa0:	/* forwardingInfo */
	GSM_SS_START_SUBTREE(tree, saved_offset, tag, "Forwarding Info",
	    gsm_ss_ett[GSM_SS_ETT_SEQUENCE],
	    &def_len, &len, subtree);

	start_offset = asn1->offset;

	if (tcap_check_tag(asn1, 0x04))
	{
	    saved_offset = asn1->offset;
	    asn1_id_decode1(asn1, &tag);

	    GSM_SS_PARAM_DISPLAY(subtree, saved_offset, tag, GSM_SS_P_SS_CODE, "SS-Code");
	}

	param_forwardingFeatureList(asn1, subtree, len - (asn1->offset - start_offset));

	if (!def_len)
	{
	    saved_offset = asn1->offset;
	    asn1_eoc_decode(asn1, -1);

	    proto_tree_add_text(subtree, asn1->tvb,
		saved_offset, asn1->offset - saved_offset, "End of Contents");
	}
	break;

    case 0xa1:	/* callBarringInfo */
	GSM_SS_START_SUBTREE(tree, saved_offset, tag, "Call Barring Info",
	    gsm_ss_ett[GSM_SS_ETT_SEQUENCE],
	    &def_len, &len, subtree);

	start_offset = asn1->offset;

	if (tcap_check_tag(asn1, 0x04))
	{
	    saved_offset = asn1->offset;
	    asn1_id_decode1(asn1, &tag);

	    GSM_SS_PARAM_DISPLAY(subtree, saved_offset, tag, GSM_SS_P_SS_CODE, "SS-Code");
	}

	param_callBarringFeatureList(asn1, subtree, len - (asn1->offset - start_offset));

	if (!def_len)
	{
	    saved_offset = asn1->offset;
	    asn1_eoc_decode(asn1, -1);

	    proto_tree_add_text(subtree, asn1->tvb,
		saved_offset, asn1->offset - saved_offset, "End of Contents");
	}
	break;

    case 0xa3:	/* ss-Data */
	GSM_SS_START_SUBTREE(tree, saved_offset, tag, "ss-Data",
	    gsm_ss_ett[GSM_SS_ETT_SEQUENCE],
	    &def_len, &len, subtree);

	start_offset = asn1->offset;

	param_ssData(asn1, subtree, len - (asn1->offset - start_offset));

	if (!def_len)
	{
	    saved_offset = asn1->offset;
	    asn1_eoc_decode(asn1, -1);

	    proto_tree_add_text(subtree, asn1->tvb,
		saved_offset, asn1->offset - saved_offset, "End of Contents");
	}
	break;

    default:
	GSM_SS_START_SUBTREE(tree, saved_offset, tag, "Unexpected TAG",
	    gsm_ss_ett[GSM_SS_ETT_SEQUENCE],
	    &def_len, &len, subtree);

	op_generic_ss(asn1, subtree, len);

	if (!def_len)
	{
	    saved_offset = asn1->offset;
	    asn1_eoc_decode(asn1, -1);

	    proto_tree_add_text(subtree, asn1->tvb,
		saved_offset, asn1->offset - saved_offset, "End of Contents");
	}
	break;
    }
}

static void
param_ssForBS(ASN1_SCK *asn1, proto_tree *tree)
{
    guint		saved_offset, start_offset;
    guint		tag, len, rem_len;
    gboolean		def_len = FALSE;
    proto_tree		*subtree;

    saved_offset = asn1->offset;
    asn1_id_decode1(asn1, &tag);

    GSM_SS_START_SUBTREE(tree, saved_offset, tag, "Sequence",
	gsm_ss_ett[GSM_SS_ETT_SEQUENCE],
	&def_len, &len, subtree);

    start_offset = asn1->offset;

    saved_offset = asn1->offset;
    asn1_id_decode1(asn1, &tag);

    GSM_SS_PARAM_DISPLAY(subtree, saved_offset, tag, GSM_SS_P_SS_CODE, "SS-Code");

    if (tcap_check_tag(asn1, 0x82))
    {
	saved_offset = asn1->offset;
	asn1_id_decode1(asn1, &tag);

	GSM_SS_PARAM_DISPLAY(subtree, saved_offset, tag, GSM_SS_P_BEARERSERVICE, "Bearerservice");
    }

    if (tcap_check_tag(asn1, 0x83))
    {
	saved_offset = asn1->offset;
	asn1_id_decode1(asn1, &tag);

	GSM_SS_PARAM_DISPLAY(subtree, saved_offset, tag, GSM_SS_P_TELESERVICE, "Teleservice");
    }

    if (tcap_check_tag(asn1, 0x84))
    {
	saved_offset = asn1->offset;
	asn1_id_decode1(asn1, &tag);

	GSM_SS_PARAM_DISPLAY(subtree, saved_offset, tag, GSM_SS_P_NONE, "Long FTN supported");
    }

    rem_len = len - (asn1->offset - start_offset);

    if (rem_len > 0)
    {
	op_generic_ss(asn1, subtree, rem_len);
    }

    if (!def_len)
    {
	saved_offset = asn1->offset;
	asn1_eoc_decode(asn1, -1);

	proto_tree_add_text(subtree, asn1->tvb,
	    saved_offset, asn1->offset - saved_offset, "End of Contents");
    }
}

static void
param_ussdArg(ASN1_SCK *asn1, proto_tree *tree)
{
    guint		saved_offset, start_offset;
    guint		tag, len, rem_len;
    gboolean		def_len = FALSE;
    proto_tree		*subtree;

    saved_offset = asn1->offset;
    asn1_id_decode1(asn1, &tag);

    GSM_SS_START_SUBTREE(tree, saved_offset, tag, "Sequence",
	gsm_ss_ett[GSM_SS_ETT_SEQUENCE],
	&def_len, &len, subtree);

    start_offset = asn1->offset;

    saved_offset = asn1->offset;
    asn1_id_decode1(asn1, &tag);

    GSM_SS_PARAM_DISPLAY(subtree, saved_offset, tag, GSM_SS_P_USSD_DCS, "USSD Data Coding Scheme");

    saved_offset = asn1->offset;
    asn1_id_decode1(asn1, &tag);

    GSM_SS_PARAM_DISPLAY(subtree, saved_offset, tag, GSM_SS_P_USSD_STRING, "USSD String");

    rem_len = len - (asn1->offset - start_offset);

    if (rem_len > 0)
    {
	op_generic_ss(asn1, subtree, rem_len);
    }

    if (!def_len)
    {
	saved_offset = asn1->offset;
	asn1_eoc_decode(asn1, -1);

	proto_tree_add_text(subtree, asn1->tvb,
	    saved_offset, asn1->offset - saved_offset, "End of Contents");
    }
}

static void
param_ussdRes(ASN1_SCK *asn1, proto_tree *tree)
{
    guint		saved_offset, start_offset;
    guint		tag, len, rem_len;
    gboolean		def_len = FALSE;
    proto_tree		*subtree;

    saved_offset = asn1->offset;
    asn1_id_decode1(asn1, &tag);

    GSM_SS_START_SUBTREE(tree, saved_offset, tag, "Sequence",
	gsm_ss_ett[GSM_SS_ETT_SEQUENCE],
	&def_len, &len, subtree);

    start_offset = asn1->offset;

    saved_offset = asn1->offset;
    asn1_id_decode1(asn1, &tag);

    GSM_SS_PARAM_DISPLAY(subtree, saved_offset, tag, GSM_SS_P_USSD_DCS, "USSD Data Coding Scheme");

    saved_offset = asn1->offset;
    asn1_id_decode1(asn1, &tag);

    GSM_SS_PARAM_DISPLAY(subtree, saved_offset, tag, GSM_SS_P_USSD_STRING, "USSD String");

    rem_len = len - (asn1->offset - start_offset);

    if (rem_len > 0)
    {
	op_generic_ss(asn1, subtree, rem_len);
    }

    if (!def_len)
    {
	saved_offset = asn1->offset;
	asn1_eoc_decode(asn1, -1);

	proto_tree_add_text(subtree, asn1->tvb,
	    saved_offset, asn1->offset - saved_offset, "End of Contents");
    }
}


/* MESSAGES */

static void
op_generic_ss(ASN1_SCK *asn1, proto_tree *tree, guint exp_len)
{
    guint	orig_offset, saved_offset, len_offset;
    guint	tag, len;
    gboolean	def_len = FALSE;
    proto_item	*item;
    proto_tree	*subtree;

    orig_offset = asn1->offset;

    while ((tvb_length_remaining(asn1->tvb, asn1->offset) > 0) &&
	(!tcap_check_tag(asn1, 0)))
    {
	if ((exp_len != 0) &&
	    ((asn1->offset - orig_offset) >= exp_len))
	{
	    break;
	}

	saved_offset = asn1->offset;
	asn1_id_decode1(asn1, &tag);

	if (TCAP_CONSTRUCTOR(tag))
	{
	    GSM_SS_START_SUBTREE(tree, saved_offset, tag, "Sequence",
		gsm_ss_ett[GSM_SS_ETT_SEQUENCE],
		&def_len, &len, subtree);

	    op_generic_ss(asn1, subtree, len);

	    if (!def_len)
	    {
		saved_offset = asn1->offset;
		asn1_eoc_decode(asn1, -1);

		proto_tree_add_text(subtree, asn1->tvb,
		    saved_offset, asn1->offset - saved_offset, "End of Contents");
	    }
	    continue;
	}

	len_offset = asn1->offset;
	asn1_length_decode(asn1, &def_len, &len);

	if (!def_len)
	{
	    proto_tree_add_text(tree, asn1->tvb,
		saved_offset, len_offset - saved_offset,
		"Tag: 0x%02x", tag);

	    proto_tree_add_text(tree, asn1->tvb,
		len_offset, asn1->offset - len_offset, "Length: Indefinite");

	    len = tcap_find_eoc(asn1);

	    op_generic_ss(asn1, tree, len);

	    saved_offset = asn1->offset;
	    asn1_eoc_decode(asn1, -1);

	    proto_tree_add_text(tree, asn1->tvb,
		saved_offset, asn1->offset - saved_offset, "End of Contents");
	    continue;
	}

	item =
	    proto_tree_add_text(tree, asn1->tvb,
		saved_offset, (asn1->offset - saved_offset) + len, "Parameter");

	subtree = proto_item_add_subtree(item, gsm_ss_ett[GSM_SS_ETT_PARAM]);

	proto_tree_add_text(subtree, asn1->tvb,
	    saved_offset, len_offset - saved_offset,
	    "Tag: 0x%02x", tag);

	proto_tree_add_text(subtree, asn1->tvb,
	    len_offset, asn1->offset - len_offset, "Length: %d", len);

	if (len > 0)
	{
	    proto_tree_add_text(subtree, asn1->tvb,
		asn1->offset, len, "Parameter Data");

	    asn1->offset += len;
	}
    }
}

static void
op_register_ss(ASN1_SCK *asn1, proto_tree *tree, guint exp_len)
{
    guint	saved_offset, start_offset;
    guint	tag, len, rem_len;
    gboolean	def_len = FALSE;
    proto_tree	*subtree;

    exp_len = exp_len;

    if (tvb_length_remaining(asn1->tvb, asn1->offset) <= 0) return;

    saved_offset = asn1->offset;
    asn1_id_decode1(asn1, &tag);

    GSM_SS_START_SUBTREE(tree, saved_offset, tag, "Sequence",
	gsm_ss_ett[GSM_SS_ETT_SEQUENCE],
	&def_len, &len, subtree);

    start_offset = asn1->offset;

    saved_offset = asn1->offset;
    asn1_id_decode1(asn1, &tag);

    GSM_SS_PARAM_DISPLAY(subtree, saved_offset, tag, GSM_SS_P_SS_CODE, "SS-Code");

    if (tcap_check_tag(asn1, 0x82))
    {
	saved_offset = asn1->offset;
	asn1_id_decode1(asn1, &tag);

	GSM_SS_PARAM_DISPLAY(subtree, saved_offset, tag, GSM_SS_P_BEARERSERVICE, "Bearerservice");
    }

    if (tcap_check_tag(asn1, 0x83))
    {
	saved_offset = asn1->offset;
	asn1_id_decode1(asn1, &tag);

	GSM_SS_PARAM_DISPLAY(subtree, saved_offset, tag, GSM_SS_P_TELESERVICE, "Teleservice");
    }

    if (tcap_check_tag(asn1, 0x84))
    {
	saved_offset = asn1->offset;
	asn1_id_decode1(asn1, &tag);

	GSM_SS_PARAM_DISPLAY(subtree, saved_offset, tag, GSM_SS_P_FORWARD_TO_NUM, "Forwarded to Number");
    }

    if (tcap_check_tag(asn1, 0x86))
    {
	saved_offset = asn1->offset;
	asn1_id_decode1(asn1, &tag);

	GSM_SS_PARAM_DISPLAY(subtree, saved_offset, tag, GSM_SS_P_NONE, "Forwarded to Subaddress");
    }

    if (tcap_check_tag(asn1, 0x85))
    {
	saved_offset = asn1->offset;
	asn1_id_decode1(asn1, &tag);

	GSM_SS_PARAM_DISPLAY(subtree, saved_offset, tag, GSM_SS_P_NONE, "No Reply Condition Time");
    }

    if (tcap_check_tag(asn1, 0x87))
    {
	saved_offset = asn1->offset;
	asn1_id_decode1(asn1, &tag);

	GSM_SS_PARAM_DISPLAY(subtree, saved_offset, tag, GSM_SS_P_NONE, "Default Priority");
    }

    if (tcap_check_tag(asn1, 0x88))
    {
	saved_offset = asn1->offset;
	asn1_id_decode1(asn1, &tag);

	GSM_SS_PARAM_DISPLAY(subtree, saved_offset, tag, GSM_SS_P_NONE, "Number Users");
    }

    if (tcap_check_tag(asn1, 0x89))
    {
	saved_offset = asn1->offset;
	asn1_id_decode1(asn1, &tag);

	GSM_SS_PARAM_DISPLAY(subtree, saved_offset, tag, GSM_SS_P_NONE, "Long FTN supported");
    }

    rem_len = len - (asn1->offset - start_offset);

    if (rem_len > 0)
    {
	op_generic_ss(asn1, subtree, rem_len);
    }

    if (!def_len)
    {
	saved_offset = asn1->offset;
	asn1_eoc_decode(asn1, -1);

	proto_tree_add_text(subtree, asn1->tvb,
	    saved_offset, asn1->offset - saved_offset, "End of Contents");
    }
}

static void
op_register_ss_rr(ASN1_SCK *asn1, proto_tree *tree, guint exp_len)
{
    guint	saved_offset;

    exp_len = exp_len;

    if (tvb_length_remaining(asn1->tvb, asn1->offset) <= 0) return;

    saved_offset = asn1->offset;

    param_ssInfo(asn1, tree);
}

static void
op_erase_ss(ASN1_SCK *asn1, proto_tree *tree, guint exp_len)
{
    guint	saved_offset;

    exp_len = exp_len;

    if (tvb_length_remaining(asn1->tvb, asn1->offset) <= 0) return;

    saved_offset = asn1->offset;

    param_ssForBS(asn1, tree);
}

static void
op_erase_ss_rr(ASN1_SCK *asn1, proto_tree *tree, guint exp_len)
{
    guint	saved_offset;

    exp_len = exp_len;

    if (tvb_length_remaining(asn1->tvb, asn1->offset) <= 0) return;

    saved_offset = asn1->offset;

    param_ssInfo(asn1, tree);
}

static void
op_activate_ss(ASN1_SCK *asn1, proto_tree *tree, guint exp_len)
{
    guint	saved_offset;

    exp_len = exp_len;

    if (tvb_length_remaining(asn1->tvb, asn1->offset) <= 0) return;

    saved_offset = asn1->offset;

    param_ssForBS(asn1, tree);
}

static void
op_activate_ss_rr(ASN1_SCK *asn1, proto_tree *tree, guint exp_len)
{
    guint	saved_offset;

    exp_len = exp_len;

    if (tvb_length_remaining(asn1->tvb, asn1->offset) <= 0) return;

    saved_offset = asn1->offset;

    param_ssInfo(asn1, tree);
}

static void
op_deactivate_ss(ASN1_SCK *asn1, proto_tree *tree, guint exp_len)
{
    guint	saved_offset;

    exp_len = exp_len;

    if (tvb_length_remaining(asn1->tvb, asn1->offset) <= 0) return;

    saved_offset = asn1->offset;

    param_ssForBS(asn1, tree);
}

static void
op_deactivate_ss_rr(ASN1_SCK *asn1, proto_tree *tree, guint exp_len)
{
    guint	saved_offset;

    exp_len = exp_len;

    if (tvb_length_remaining(asn1->tvb, asn1->offset) <= 0) return;

    saved_offset = asn1->offset;

    param_ssInfo(asn1, tree);
}

static void
op_interrogate_ss(ASN1_SCK *asn1, proto_tree *tree, guint exp_len)
{
    guint	saved_offset;

    exp_len = exp_len;

    if (tvb_length_remaining(asn1->tvb, asn1->offset) <= 0) return;

    saved_offset = asn1->offset;

    param_ssForBS(asn1, tree);
}

static void
op_interrogate_ss_rr(ASN1_SCK *asn1, proto_tree *tree, guint exp_len)
{
    guint	saved_offset;
    guint	tag;

    exp_len = exp_len;

    if (tvb_length_remaining(asn1->tvb, asn1->offset) <= 0) return;

    saved_offset = asn1->offset;
    asn1_id_decode1(asn1, &tag);

    switch (tag)
    {
    case 0x80:	/* SS-Status */
	GSM_SS_PARAM_DISPLAY(tree, saved_offset, tag, GSM_SS_P_SS_STATUS, "SS-Status");
	break;

    case 0x82:	/* BasicServiceGroupList */
	/* XXX */
	asn1->offset = saved_offset;
	op_generic_ss(asn1, tree, exp_len);
	break;

    case 0x83:	/* ForwardingFeatureList */
	asn1->offset = saved_offset;
	param_forwardingFeatureList(asn1, tree, exp_len);
	break;

    case 0x84:	/* GenericServiceInfo */
	/* XXX */
	asn1->offset = saved_offset;
	op_generic_ss(asn1, tree, exp_len);
	break;

    default:
	asn1->offset = saved_offset;
	op_generic_ss(asn1, tree, exp_len);
	return;
    }
}

static void
op_reg_password(ASN1_SCK *asn1, proto_tree *tree, guint exp_len)
{
    guint	saved_offset;
    guint	tag, rem_len;

    exp_len = exp_len;

    if (tvb_length_remaining(asn1->tvb, asn1->offset) <= 0) return;

    saved_offset = asn1->offset;
    asn1_id_decode1(asn1, &tag);

    GSM_SS_PARAM_DISPLAY(tree, saved_offset, tag, GSM_SS_P_SS_CODE, "SS-Code");

    rem_len = exp_len - (asn1->offset - saved_offset);

    if (rem_len > 0)
    {
	op_generic_ss(asn1, tree, rem_len);
    }
}

static void
op_reg_password_rr(ASN1_SCK *asn1, proto_tree *tree, guint exp_len)
{
    guint	saved_offset;
    guint	tag, rem_len;

    exp_len = exp_len;

    if (tvb_length_remaining(asn1->tvb, asn1->offset) <= 0) return;

    saved_offset = asn1->offset;
    asn1_id_decode1(asn1, &tag);

    GSM_SS_PARAM_DISPLAY(tree, saved_offset, tag, GSM_SS_P_PASSWORD, "New Password");

    rem_len = exp_len - (asn1->offset - saved_offset);

    if (rem_len > 0)
    {
	op_generic_ss(asn1, tree, rem_len);
    }
}

static void
op_get_password(ASN1_SCK *asn1, proto_tree *tree, guint exp_len)
{
    guint	saved_offset;
    guint	tag, rem_len;

    exp_len = exp_len;

    if (tvb_length_remaining(asn1->tvb, asn1->offset) <= 0) return;

    saved_offset = asn1->offset;
    asn1_id_decode1(asn1, &tag);

    GSM_SS_PARAM_DISPLAY(tree, saved_offset, tag, GSM_SS_P_GUIDANCE_INFO, "Guidance Info");

    rem_len = exp_len - (asn1->offset - saved_offset);

    if (rem_len > 0)
    {
	op_generic_ss(asn1, tree, rem_len);
    }
}

static void
op_get_password_rr(ASN1_SCK *asn1, proto_tree *tree, guint exp_len)
{
    guint	saved_offset;
    guint	tag, rem_len;

    exp_len = exp_len;

    if (tvb_length_remaining(asn1->tvb, asn1->offset) <= 0) return;

    saved_offset = asn1->offset;
    asn1_id_decode1(asn1, &tag);

    GSM_SS_PARAM_DISPLAY(tree, saved_offset, tag, GSM_SS_P_PASSWORD, "Current Password");

    rem_len = exp_len - (asn1->offset - saved_offset);

    if (rem_len > 0)
    {
	op_generic_ss(asn1, tree, rem_len);
    }
}

static void
op_proc_uss_data(ASN1_SCK *asn1, proto_tree *tree, guint exp_len)
{
    guint	saved_offset;
    guint	tag, rem_len;

    exp_len = exp_len;

    if (tvb_length_remaining(asn1->tvb, asn1->offset) <= 0) return;

    saved_offset = asn1->offset;

    if (tcap_check_tag(asn1, 0x16))
    {
	saved_offset = asn1->offset;
	asn1_id_decode1(asn1, &tag);

	GSM_SS_PARAM_DISPLAY(tree, saved_offset, tag, GSM_SS_P_IA5_STRING, "SS-UserData");
    }

    rem_len = exp_len - (asn1->offset - saved_offset);

    if (rem_len > 0)
    {
	op_generic_ss(asn1, tree, rem_len);
    }
}

static void
op_proc_uss_data_rr(ASN1_SCK *asn1, proto_tree *tree, guint exp_len)
{
    guint	saved_offset;
    guint	tag, rem_len;

    exp_len = exp_len;

    if (tvb_length_remaining(asn1->tvb, asn1->offset) <= 0) return;

    saved_offset = asn1->offset;

    if (tcap_check_tag(asn1, 0x16))
    {
	saved_offset = asn1->offset;
	asn1_id_decode1(asn1, &tag);

	GSM_SS_PARAM_DISPLAY(tree, saved_offset, tag, GSM_SS_P_IA5_STRING, "SS-UserData");
    }

    rem_len = exp_len - (asn1->offset - saved_offset);

    if (rem_len > 0)
    {
	op_generic_ss(asn1, tree, rem_len);
    }
}

static void
op_proc_uss_req(ASN1_SCK *asn1, proto_tree *tree, guint exp_len)
{
    guint	saved_offset;

    exp_len = exp_len;

    if (tvb_length_remaining(asn1->tvb, asn1->offset) <= 0) return;

    saved_offset = asn1->offset;

    param_ussdArg(asn1, tree);
}

static void
op_proc_uss_req_rr(ASN1_SCK *asn1, proto_tree *tree, guint exp_len)
{
    guint	saved_offset;

    exp_len = exp_len;

    if (tvb_length_remaining(asn1->tvb, asn1->offset) <= 0) return;

    saved_offset = asn1->offset;

    param_ussdRes(asn1, tree);
}

static void
op_uss_req(ASN1_SCK *asn1, proto_tree *tree, guint exp_len)
{
    guint	saved_offset;

    exp_len = exp_len;

    if (tvb_length_remaining(asn1->tvb, asn1->offset) <= 0) return;

    saved_offset = asn1->offset;

    param_ussdArg(asn1, tree);
}

static void
op_uss_req_rr(ASN1_SCK *asn1, proto_tree *tree, guint exp_len)
{
    guint	saved_offset;

    exp_len = exp_len;

    if (tvb_length_remaining(asn1->tvb, asn1->offset) <= 0) return;

    saved_offset = asn1->offset;

    param_ussdRes(asn1, tree);
}

static void
op_uss_notify(ASN1_SCK *asn1, proto_tree *tree, guint exp_len)
{
    guint	saved_offset;

    exp_len = exp_len;

    if (tvb_length_remaining(asn1->tvb, asn1->offset) <= 0) return;

    saved_offset = asn1->offset;

    param_ussdArg(asn1, tree);
}

#define	GSM_SS_NUM_OP (sizeof(gsm_ss_opr_code_strings)/sizeof(value_string))
static void (*op_fcn[])(ASN1_SCK *asn1, proto_tree *tree, guint exp_len) = {
    op_register_ss,	/* RegisterSS */
    op_erase_ss,	/* EraseSS */
    op_activate_ss,	/* ActivateSS */
    op_deactivate_ss,	/* DeactivateSS */
    op_interrogate_ss,	/* InterrogateSS */
    NULL,	/* NotifySS */
    op_reg_password,	/* RegisterPassword */
    op_get_password,	/* GetPassword */
    op_proc_uss_data,	/* ProcessUnstructuredSS-Data */
    NULL,	/* ForwardCheckSS-Indication */
    op_proc_uss_req,	/* ProcessUnstructuredSS-Request */
    op_uss_req,		/* UnstructuredSS-Request */
    op_uss_notify,	/* UnstructuredSS-Notify */
    NULL,	/* EraseCC-Entry */
    NULL,	/* LCS-LocationNotification */
    NULL,	/* LCS-MOLR */
    NULL,	/* AccessRegisterCCEntry */
    NULL,	/* ForwardCUG-Info */
    NULL /* NO ARGS */,	/* SplitMPTY */
    NULL /* NO ARGS */,	/* RetrieveMPTY */
    NULL /* NO ARGS */,	/* HoldMPTY */
    NULL /* NO ARGS */,	/* BuildMPTY */
    NULL,	/* ForwardChargeAdvice */
    NULL,	/* ExplicitCT */
    NULL,	/* LCS-LocationNotification */
    NULL,	/* LCS-MOLR */

    NULL	/* NONE */
};

static void (*op_fcn_rr[])(ASN1_SCK *asn1, proto_tree *tree, guint exp_len) = {
    op_register_ss_rr,		/* RegisterSS */
    op_erase_ss_rr,		/* EraseSS */
    op_activate_ss_rr,		/* ActivateSS */
    op_deactivate_ss_rr,	/* DeactivateSS */
    op_interrogate_ss_rr,	/* InterrogateSS */
    NULL,	/* NotifySS */
    op_reg_password_rr,		/* RegisterPassword */
    op_get_password_rr,		/* GetPassword */
    op_proc_uss_data_rr,	/* ProcessUnstructuredSS-Data */
    NULL,	/* ForwardCheckSS-Indication */
    op_proc_uss_req_rr,		/* ProcessUnstructuredSS-Request */
    op_uss_req_rr,		/* UnstructuredSS-Request */
    NULL /* NO ARGS */,		/* UnstructuredSS-Notify */
    NULL,	/* EraseCC-Entry */
    NULL,	/* LCS Location Notification */
    NULL,	/* LCS MOLR */
    NULL,	/* AccessRegisterCCEntry */
    NULL,	/* ForwardCUG-Info */
    NULL,	/* SplitMPTY */
    NULL,	/* RetrieveMPTY */
    NULL,	/* HoldMPTY */
    NULL,	/* BuildMPTY */
    NULL /* NO ARGS */,		/* ForwardChargeAdvice */
    NULL,	/* ExplicitCT */
    NULL,	/* LCS-LocationNotification */
    NULL,	/* LCS-MOLR */

    NULL	/* NONE */
};

void
gsm_ss_dissect(ASN1_SCK *asn1, proto_tree *tree, guint exp_len,
    guint opr_code, guint comp_type_tag)
{
    void (*dissect_fcn)(ASN1_SCK *asn1, proto_tree *tree, guint exp_len);
    gchar	*str;
    gint	op_idx;


    dissect_fcn = NULL;

    str = my_match_strval(opr_code, gsm_ss_opr_code_strings, &op_idx);

    if (str != NULL)
    {
	switch (comp_type_tag)
	{
	case TCAP_COMP_INVOKE:
	    dissect_fcn = op_fcn[op_idx];
	    break;

	case TCAP_COMP_RRL:
	    dissect_fcn = op_fcn_rr[op_idx];
	    break;

	case TCAP_COMP_RE:
	    dissect_fcn = NULL;
	    return;

	default:
	    /*
	     * no parameters should be present in the component types
	     * ignore
	     */
	    return;
	}
    }

    if (dissect_fcn == NULL)
    {
	op_generic_ss(asn1, tree, exp_len);
    }
    else
    {
	(*dissect_fcn)(asn1, tree, exp_len);
    }
}
