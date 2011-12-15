/* packet-sgsap.c
 * Routines for SGs Application Part (SGsAP) protocol dissection
 *
 * Copyright 2010 - 2011, Anders Broman <anders.broman@ericsson.com>
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
 * References: 3GPP TS 29.118 V10.2.0 (2010-12)
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/asn1.h>

#include "packet-gsm_a_common.h"
#include "packet-e212.h"

#define PNAME  "SGs Application Part (SGsAP)"
#define PSNAME "SGSAP"
#define PFNAME "sgsap"

/* The registered SCTP port number for SGsAP is 29118.
 * The payload protocol identifier to be used for SGsAP is 0.
 */
#define SCTP_PORT_SGSAP	29118


/* Global variables */
static dissector_handle_t gsm_a_dtap_handle;
static packet_info *gpinfo;
static guint gbl_sgsapSctpPort=SCTP_PORT_SGSAP;


/* Initialize the protocol and registered fields */
static int proto_sgsap = -1;

static int hf_sgsap_msg_type = -1;
int hf_sgsap_elem_id = -1;
static int hf_sgsap_eps_location_update_type = -1;
static int hf_sgsap_service_indicator_value = -1;
static int hf_sgsap_sgs_cause = -1;
static int hf_sgsap_ue_emm_mode = -1;
static int hf_sgsap_eci	= -1;
static int hf_sgsap_cn_id = -1;
static int hf_sgsap_imsi_det_eps = -1;
static int hf_sgsap_lcs_indic = -1;
static int hf_sgsap_mme_name = -1;
static int hf_sgsap_vlr_name = -1;
static int hf_sgsap_imeisv = -1;

static int ett_sgsap = -1;

/*
 * 9.4	Information elements
 */
/*
 * 9.4.1	CLI
 */

/*
 * Octets 3 to 14 contain the value part of the Calling party BCD number information element
 * defined in subclause 10.5.4.9 of 3GPP TS 24.008 [8] (octets 3 to 14, i.e. not including
 * 3GPP TS 24.008 IEI and 3GPP TS 24.008 length indicator)
 * ( packet-gsm_a_dtap.c )
 */
/*
 * 9.4.2	EPS location update type
 */

/* EPS location update type value (octet 3) */
static const value_string sgsap_eps_location_update_type_values[] = {
	{ 0x00,	"Shall not be sent in this version of the protocol" },
	{ 0x01,	"IMSI attach" },
	{ 0x02,	"Normal location update" },
	{ 0, NULL }
};

static guint16
de_sgsap_eps_loc_upd_type(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;
	guint8 oct;

	curr_offset = offset;

	/* Octet 3	EPS location update type value */
	proto_tree_add_item(tree, hf_sgsap_eps_location_update_type, tvb, offset, 1, ENC_BIG_ENDIAN);
	if(add_string){
		oct = tvb_get_guint8(tvb,curr_offset);
		g_snprintf(add_string, string_len, " - %s", val_to_str_const(oct, sgsap_eps_location_update_type_values, "Reserved"));
	}

	curr_offset++;

	return(curr_offset - offset);
}
/*
 * 9.4.3	Erroneous message
 *
 * See subclause 18.4.5 in 3GPP TS 29.018 [16].
 */
static guint16
de_sgsap_err_msg(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	/* 18.4.5 Erroneous message
	 * The Erroneous message IE is a TLV IE that encapsulates the message in error.
	 * Octet 3 - Octet n
	 * Erroneous message including the message type.
	 */
	proto_tree_add_item(tree, hf_sgsap_msg_type, tvb, offset, 1, ENC_BIG_ENDIAN);

	return(len);
}
/*
 * 9.4.3a	E-UTRAN Cell Global Identity
 *
 * The coding of the E-UTRAN Cell Global Identity value is according to ECGI field information element
 * as specified in subclause 8.21.5 of 3GPP TS 29.274 [17A] (GTPv2-C)
 */
static guint16
de_sgsap_ecgi(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32    curr_offset;

    curr_offset = offset;

    dissect_e212_mcc_mnc(tvb, gpinfo, tree, offset, TRUE);
    curr_offset+=3;

    proto_tree_add_item(tree, hf_sgsap_eci, tvb, curr_offset, 4, ENC_BIG_ENDIAN);
    curr_offset+=4;

    return(curr_offset-offset);
}
/*
 * 9.4.4	Global CN-Id
 *
 * See subclause 18.4.27 in 3GPP TS 29.018 [16].
 * 18.4.27 Global CN-Id
 * The Global CN-Id consists of a PLMN-Id and a CN-Id, see 3GPP TS 23.003. The PLMN-Id consists of MCC and MNC
 * coded according to Location Area Identification in 3GPP TS 24.008. The CN-Id is an integer defined by O&M. The
 * least significant bit of the CN-Id field is bit 1 of octet 7 and the most significant bit is bit 8 of octet 6. If the CN-Id does
 * not fill the field reserved for it, the rest of the bits are set to '0'.
 */
static guint16
de_sgsap_g_cn_id(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32    curr_offset;

    curr_offset = offset;

    dissect_e212_mcc_mnc(tvb, gpinfo, tree, offset, TRUE);
    curr_offset+=3;

    proto_tree_add_item(tree, hf_sgsap_cn_id, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
    curr_offset+=2;

    return(curr_offset-offset);
}
/*
 * 9.4.5	IMEISV
 * See subclause 18.4.9 in 3GPP TS 29.018 [16].
 * The IMEISV is coded as a sequence of BCD digits, compressed two into each octet.
 * The IMEISV consists of 16 digits
 * (see 3GPP TS 23.003).
 */
static guint16
de_sgsap_imeisv(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	const char  *imeisv_str;
    guint32		curr_offset;

    curr_offset = offset;

	imeisv_str = tvb_bcd_dig_to_ep_str( tvb, curr_offset, len, NULL, FALSE);
	proto_tree_add_string(tree, hf_sgsap_imeisv, tvb, curr_offset, len, imeisv_str);
	if (add_string){
		/* (len<<2)+4 = the maximum number of bytes to produce (including the terminating nul character). */
		g_snprintf(add_string, (len<<2)+4, " - %s", imeisv_str);
	}

    return(len);
}

/*
 * 9.4.6	IMSI
 * See subclause 18.4.10 in 3GPP TS 29.018 [16].
 */
/* The IMSI is coded as a sequence of BCD digits, compressed two into each octet.
 * This is a variable length element, and includes a length indicator.
 * The IMSI is defined in 3GPP TS 23.003. It shall not exceed 15 digits (see 3GPP TS 23.003).
 */
/*
 * 9.4.7	IMSI detach from EPS service type
 */

/* IMSI detach from EPS service type value (octet 3) */
static const value_string sgsap_imsi_det_from_eps_serv_type_values[] = {
	{ 0x00,	"Interpreted as reserved in this version of the protocol" },
	{ 0x01,	"Network initiated IMSI detach from EPS services" },
	{ 0x02,	"UE initiated IMSI detach from EPS services" },
	{ 0x03,	"EPS services not allowed" },
	{ 0, NULL }
};

static guint16
de_sgsap_imsi_det_eps(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	proto_tree_add_item(tree, hf_sgsap_imsi_det_eps, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	curr_offset+=1;

	return(curr_offset-offset);
}
/*
 * 9.4.8	IMSI detach from non-EPS service type
 */
/* IMSI detach from non-EPS service type value (octet 3)*/
static const value_string sgsap_imsi_det_from_non_eps_serv_type_values[] = {
	{ 0x00,	"Interpreted as reserved in this version of the protocol" },
	{ 0x01,	"Explicit UE initiated IMSI detach from non-EPS services" },
	{ 0x02,	"Combined UE initiated IMSI detach from EPS and non-EPS services" },
	{ 0x03,	"Implicit network initiated IMSI detach from non-EPS services" },
	{ 0, NULL }
};

static guint16
de_sgsap_imsi_det_non_eps(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	proto_tree_add_item(tree, hf_sgsap_imsi_det_eps, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	curr_offset+=1;

	return(curr_offset-offset);
}
/*
 * 9.4.9	LCS client identity
 * The coding of the LCS client identity value is according to LCS-ClientID
 * as specified in subclause 17.7.13 of 3GPP TS 29.002 [15]
 * (packet-nas_eps.c)
 */
/*
 * 9.4.10	LCS indicator
 */
static const value_string sgsap_lcs_indic_values[] = {
	{ 0x00,	"Normal, unspecified in this version of the protocol" },
	{ 0x01,	"MT-LR" },
	{ 0, NULL }
};

static guint16
de_sgsap_lcs_indic(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	proto_tree_add_item(tree, hf_sgsap_lcs_indic, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	curr_offset+=1;

	return(curr_offset-offset);
}
/*
 * 9.4.11	Location area identifier
 *
 * Octets 3 to 7 contain the value part of the Location area identification information element
 * defined in 3GPP TS 24.008 [8] (starting with octet 2, i.e. not including 3GPP TS 24.008 IEI)
 *(packet-gsm_a_common.c)
 */
/*
 * 9.4.12	MM information
 * For the coding see subclause 18.4.16 in 3GPP TS 29.018 [16].
 * User information: This field is composed of one or more of the
 * information elements of the MM information message as defined in
 * 3GPP TS 24.008, excluding the Protocol discriminator, Skip
 * indicator and Message type. This field includes the IEI and length
 * indicatior of the other information elements.
 */
static guint16
de_sgsap_mm_info(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	dtap_mm_mm_info(tvb, tree, pinfo, curr_offset, len);

	return(len);
}

/*
 * 9.4.13	MME name
 */
static guint16
de_sgsap_mme_name(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint   name_len, tmp;
	guint8 	*fqdn = NULL;

	/* The MME name information element specifies the MME name and is coded as shown in figure 9.4.13.1. Octets 3
	 * through n contain the name in the form of a fully qualified domain name (FQDN) as specified in 3GPP TS 23.003 [3].
	 * The value part of the MME name information element (not including IEI and length indicator) shall have a length of 55
	 * octets.
	 */
	if (len > 0) {
		name_len = tvb_get_guint8(tvb, offset);

		if (name_len < 0x20) {
			fqdn = tvb_get_ephemeral_string(tvb, offset + 1, len - 1);
			for (;;) {
				if (name_len >= len - 1)
					break;
				tmp = name_len;
				name_len = name_len + fqdn[tmp] + 1;
				fqdn[tmp] = '.';
			}
		} else{
			fqdn = tvb_get_ephemeral_string(tvb, offset, len);
		}
		proto_tree_add_string(tree, hf_sgsap_mme_name, tvb, offset, len, fqdn);
		if (add_string)
			g_snprintf(add_string, string_len, " - %s", fqdn);

	}

	return(len);
}
/*
 * 9.4.14	Mobile identity
 * See subclause 18.4.17 in 3GPP TS 29.018 [16].
 * (packet-gsm_a_common.c)
 */
/*
 * 9.4.14a	Mobile Station Classmark 2
 * With the exception of the IEI, the contents are specified in subclause 10.5.1.6 in 3GPP TS 24.008 [8].
 * (packet-gsm_a_common.c)
 */
/*
 * 9.4.15	NAS message container
 * Octets 3 to 253 contain the SMS message (i.e. CP DATA, CP ACK or CP ERROR)
 * as defined in subclause 7.2 of 3GPP TS 24.011 [10]
 */
static guint16
de_sgsap_nas_msg_container(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	tvbuff_t *new_tvb;
	guint32	curr_offset;

	curr_offset = offset;

	/* Octets 3 to 253 contain the SMS message (i.e. CP DATA, CP ACK or CP ERROR)
	 * as defined in subclause 7.2 of 3GPP TS 24.011 [10]
	 */
	new_tvb = tvb_new_subset(tvb, curr_offset,len, len);
	if(gsm_a_dtap_handle){
		call_dissector(gsm_a_dtap_handle,new_tvb,gpinfo, tree);
	}

	return(len);
}
/*
 * 9.4.16	Reject cause
 * See subclause 18.4.21 in 3GPP TS 29.018 [16].
 * The rest of the information element is coded as the value part of
 * the reject cause IE defined in 3GPP TS 24.008, not including
 * 3GPP TS 24.008 IEI.
 * (packet-gsm_a_dtap.c)
 */
/*
 * 9.4.17	Service indicator
 */

/* Octet 3	Service indicator value */
static const value_string sgsap_service_indicator_values[] = {
	{ 0x00,	"Shall not be sent in this version of the protocol" },
	{ 0x01,	"CS call indicator" },
	{ 0x02,	"SMS indicator" },
	{ 0, NULL }
};

static guint16
de_sgsap_serv_indic(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;
	guint8 oct;

	curr_offset = offset;

	/* Octet 3	Service indicator value */
	proto_tree_add_item(tree, hf_sgsap_service_indicator_value, tvb, offset, 1, ENC_BIG_ENDIAN);
	if(add_string){
		oct = tvb_get_guint8(tvb,curr_offset);
		g_snprintf(add_string, string_len, " - %s", val_to_str_const(oct, sgsap_service_indicator_values, "Reserved"));
	}
	curr_offset++;

	return(curr_offset - offset);
}
/*
 * 9.4.18	SGs cause
 */

/* SGs cause value (octet 3) */
static const value_string sgsap_sgs_cause_values[] = {
	{ 0x00,	"Normal, unspecified in this version of the protocol" },
	{ 0x01,	"IMSI detached for EPS services" },
	{ 0x02,	"IMSI detached for EPS and non-EPS services" },
	{ 0x03,	"IMSI unknown" },
	{ 0x04,	"IMSI detached for non-EPS services" },
	{ 0x05,	"IMSI implicitly detached for non-EPS services" },
	{ 0x06,	"UE unreachable" },
	{ 0x07,	"Message not compatible with the protocol state" },
	{ 0x08,	"Missing mandatory information element" },
	{ 0x09,	"Invalid mandatory information" },
	{ 0x0a,	"Conditional information element error" },
	{ 0x0b,	"Semantically incorrect message" },
	{ 0x0c,	"Message unknown" },
	{ 0x0d,	"Mobile terminating CS fallback call rejected by the user" },
	{ 0, NULL }
};

static value_string_ext sgsap_sgs_cause_values_ext = VALUE_STRING_EXT_INIT(sgsap_sgs_cause_values);

static guint16
de_sgsap_sgs_cause(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;
	guint8 oct;

	curr_offset = offset;

	proto_tree_add_item(tree, hf_sgsap_sgs_cause, tvb, offset, 1, ENC_BIG_ENDIAN);
	if(add_string){
		oct = tvb_get_guint8(tvb,curr_offset);
		g_snprintf(add_string, string_len, " - %s", val_to_str_ext_const(oct, &sgsap_sgs_cause_values_ext, "Reserved"));
	}
	curr_offset++;

	return(curr_offset - offset);
}
/*
 * 9.4.19	SS code
 * The coding of the SS code value is according to SS-Code as specified in
 * subclause 17.7.5 of 3GPP TS 29.002 [15]
 * ( packet-nas_eps.c)
 */
/*
 * 9.4.20	TMSI
 * See subclause 18.4.23 in 3GPP TS 29.018 [16].
 * (packet-gsm_a_bssmap.c)
 */

/*
 * 9.4.21	TMSI status
 *
 * See subclause 18.4.24 in 3GPP TS 29.018 [16].
 * (packet-gsm_a_gm.c)
 */
/*
 * 9.4.21a	Tracking Area Identity
 * Octets 3 to 7 contain the value part of the Tracking Area Identity information element defined in 3GPP TS 24.301 [14]
 * (starting with octet 2, i.e. not including 3GPP TS 24.301 IEI)
 * (packet-nas_eps.c)
 */
/*
 * 9.4.21b	UE Time Zone
 * The coding of the UE Time Zone value is according to value part of the Time Zone information element as specified
 * in subclause 10.5.3.8 of 3GPP TS 24.008 [8] (i.e. not including 3GPP TS 24.008 IEI)
 * (packet-gsm_a_dtap.c)
 */
/*
 * 9.4.21c	UE EMM mode
 */
static const value_string sgsap_ue_emm_mode_values[] = {
	{ 0x00,	"EMM-IDLE" },
	{ 0x01,	"EMM-CONNECTED" },
	{ 0, NULL }
};

static guint16
de_sgsap_ue_emm_mode(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	proto_tree_add_item(tree, hf_sgsap_ue_emm_mode, tvb, offset, 1, ENC_BIG_ENDIAN);
	curr_offset+=1;

	return(curr_offset - offset);
}
/*
 * 9.4.22	VLR name
 */
static guint16
de_sgsap_vlr_name(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint     name_len, tmp;
	guint8 	*fqdn = NULL;

	/* The VLR name information element specifies the VLR name and is coded as shown in figure 9.4.22.1.
	 * Octets 3 through n contain the VLR name in the form of a fully qualified domain name (FQDN)
	 * as specified in IETF RFC 1035 [21].
	 */
	if (len > 0) {
		name_len = tvb_get_guint8(tvb, offset);

		if (name_len < 0x20) {
			fqdn = tvb_get_ephemeral_string(tvb, offset + 1, len - 1);
			for (;;) {
				if (name_len >= len - 1)
					break;
				tmp = name_len;
				name_len = name_len + fqdn[tmp] + 1;
				fqdn[tmp] = '.';
			}
		} else{
			fqdn = tvb_get_ephemeral_string(tvb, offset, len);
		}
		proto_tree_add_string(tree, hf_sgsap_vlr_name, tvb, offset, len, fqdn);
		if (add_string)
			g_snprintf(add_string, string_len, " - %s", fqdn);
	}

	return(len);
}

/*
 * 9.4.23	Channel needed
 * See subclause 18.4.2 in 3GPP TS 29.018 [16].
 * The rest of the information element is coded as the IEI part and the
 * value part of the Channel Needed IE defined in 3GPP TS 44.018
 * (packet-gsm_a_bssmap.c)
 */
/*
 * 9.4.24	eMLPP priority
 * See subclause 18.4.4 in 3GPP TS 29.018 [16].
 * The rest of the information element is coded as the value part of
 * the eMLPP-Priority IE defined in 3GPP TS 48.008 (not including
 * 3GPP TS 48.008 IEI and 3GPP TS 48.008 length indicator).
 * (packet-gsm_a_bssmap.c)
 */

const value_string sgsap_elem_strings[] = {
	{ 0x01,	"IMSI" },									/* 9.4.6 */
	{ 0x02,	"VLR name" },								/* 9.4.22 */
	{ 0x03,	"TMSI" },									/* 9.4.20 */
	{ 0x04,	"Location area identifier" },				/* 9.4.11 */
	{ 0x05,	"Channel Needed" },							/* 9.4.23 */
	{ 0x06,	"eMLPP Priority" },							/* 9.4.24 */
	{ 0x07,	"TMSI status" },							/* 9.4.21 */
	{ 0x08,	"SGs cause" },								/* 9.4.18 */
	{ 0x09,	"MME name" },								/* 9.4.13 */
	{ 0x0a,	"EPS location update type" },				/* 9.4.2 */
	{ 0x0b,	"Global CN-Id" },							/* 9.4.4 */

	{ 0x0c,	"Undefined" },								/*  */
	{ 0x0d,	"Undefined" },								/*  */

	{ 0x0e,	"Mobile identity" },						/* 9.4.14 */
	{ 0x0f,	"Reject cause" },							/* 9.4.16 */
	{ 0x10,	"IMSI detach from EPS service type" },		/* 9.4.7 */
	{ 0x11,	"IMSI detach from non-EPS service type" },	/* 9.4.8 */

	{ 0x15,	"IMEISV" },									/* 9.4.5 */
	{ 0x16,	"NAS message container" },					/* 9.4.15 */
	{ 0x17,	"MM information" },							/* 9.4.12 */

	{ 0x18,	"Undefined" },								/*  */
	{ 0x19,	"Undefined" },								/*  */
	{ 0x1a,	"Undefined" },								/*  */

	{ 0x1b,	"Erroneous message" },						/* 9.4.3 */
	{ 0x1c,	"CLI" },									/* 9.4.1 */
	{ 0x1d,	"LCS client identity" },					/* 9.4.9 */
	{ 0x1e, "LCS indicator" },							/* 9.4.10 */
	{ 0x1f, "SS code" },								/* 9.4.19 */
	{ 0x20, "Service indicator" },						/* 9.4.17 */
	{ 0x21, "UE Time Zone" },							/* 9.4.21b */
	{ 0x22, "Mobile Station Classmark 2" },				/* 9.4.14a */
	{ 0x23, "Tracking Area Identity" },					/* 9.4.21a */
	{ 0x24, "E-UTRAN Cell Global Identity" },			/* 9.4.3a */
	{ 0x25, "UE EMM mode" },							/* 9.4.21c */

	{ 0, NULL }
};

#define	NUM_SGSAP_ELEM (sizeof(sgsap_elem_strings)/sizeof(value_string))
gint ett_sgsap_elem[NUM_SGSAP_ELEM];
#if 0
This enum has been moved to packet-gsm_a_common to
make it possible to use element dissecton from this dissector
in other dissectors.
It is left here as a comment for easier reference.

Note this enum must be of the same size as the element decoding list

typedef enum
{

	DE_SGSAP_IMSI,									/. 9.4.6 IMSI./
	DE_SGSAP_VLR_NAME,								/. 9.4.22 VLR name./
	DE_SGSAP_TMSI,									/. 9.4.20 TMSI ./
	DE_SGSAP_LOC_AREA_ID,							/. 9.4.11 Location area identifier ./
	DE_SGSAP_CH_NEEDED,								/. 9.4.23 Channel Needed ./
	DE_SGSAP_EMLPP_PRIO,							/. 9.4.24 eMLPP Priority./
	DE_SGSAP_TMSI_STATUS,							/. 9.4.21 TMSI status ./
	DE_SGSAP_SGS_CAUSE,								/. 9.4.18 SGs cause./
	DE_SGSAP_MME_NAME,								/. 9.4.13 MME name./
	DE_SGSAP_EPS_LOC_UPD_TYPE,						/. 9.4.2 EPS location update type./
	DE_SGSAP_GLOBAL_CN_ID,							/. 9.4.4 Global CN-Id./

	DE_SGSAP_UDEF_12,								/. Undefined ./
	DE_SGSAP_UDEF_13,								/. Undefined ./

	DE_SGSAP_MID,									/. 9.4.14 Mobile identity./
	DE_SGSAP_REJ_CAUSE,								/. 9.4.16 Reject cause ./
	DE_SGSAP_IMSI_DET_EPS,							/. 9.4.7 IMSI detach from EPS service type ./
	DE_SGSAP_IMSI_DET_NON_EPS,						/. 9.4.8 IMSI detach from non-EPS service type ./

	DE_SGSAP_IMEISV,								/. 9.4.5 IMEISV ./
	DE_SGSAP_NAS_MSG_CONTAINER,						/. 9.4.15 NAS message container./
	DE_SGSAP_MM_INFO,								/. 9.4.12 MM information./

	DE_SGSAP_UDEF_24,								/. Undefined ./
	DE_SGSAP_UDEF_25,								/. Undefined ./
	DE_SGSAP_UDEF_26,								/. Undefined ./

	DE_SGSAP_ERR_MSG,								/. 9.4.3 Erroneous message./
	DE_SGSAP_CLI,									/. 9.4.1 CLI ./
	DE_SGSAP_LCS_CLIENT_ID,							/. 9.4.9 LCS client identity ./
	DE_SGSAP_LCS_INDIC,								/. 9.4.10 LCS indicator ./
	DE_SGSAP_SS_CODE,								/. 9.4.19 SS code ./
	DE_SGSAP_SERV_INDIC,							/. 9.4.17 Service indicator ./
	DE_SGSAP_UE_TZ,									/. 9.4.21b UE Time Zone ./
	DE_SGSAP_MSC_2,									/. 9.4.14a Mobile Station Classmark 2 ./
	DE_SGSAP_TAID,									/. 9.4.21a Tracking Area Identity ./
	DE_SGSAP_ECGI,									/. 9.4.3a E-UTRAN Cell Global Identity ./
	DE_SGSAP_UE_EMM_MODE,							/. 9.4.21c UE EMM mode./

	DE_SGAP_NONE							/. NONE ./
}
sgsap_elem_idx_t;
#endif /* 0 */

guint16 (*sgsap_elem_fcn[])(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len, gchar *add_string, int string_len) = {
	NULL/*DE_SGSAP_IMSI*/,									/* 9.4.6 IMSI*/
	de_sgsap_vlr_name,										/* 9.4.22 VLR name*/
	NULL/*DE_SGSAP_TMSI*/,									/* 9.4.20 TMSI */
	NULL/*DE_SGSAP_LOC_AREA_ID*/,							/* 9.4.11 Location area identifier */
	NULL/*DE_SGSAP_CH_NEEDED*/,								/* 9.4.23 Channel Needed */
	NULL/*DE_SGSAP_EMLPP_PRIO*/,							/* 9.4.24 eMLPP Priority*/
	NULL/*DE_SGSAP_TMSI_STATUS*/,							/* 9.4.21 TMSI status */
	de_sgsap_sgs_cause,										/* 9.4.18 SGs cause*/
	de_sgsap_mme_name,										/* 9.4.13 MME name*/
	de_sgsap_eps_loc_upd_type,								/* 9.4.2 EPS location update type*/
	de_sgsap_g_cn_id,										/* 9.4.4 Global CN-Id*/

	NULL/*DE_SGSAP_UDEF_12*/,								/* Undefined */
	NULL/*DE_SGSAP_UDEF_13*/,								/* Undefined */

	NULL/*DE_SGSAP_MID*/,									/* 9.4.14 Mobile identity*/
	NULL/*DE_SGSAP_REJ_CAUSE*/,								/* 9.4.16 Reject cause */
	de_sgsap_imsi_det_eps,									/* 9.4.7 IMSI detach from EPS service type */
	de_sgsap_imsi_det_non_eps,								/* 9.4.8 IMSI detach from non-EPS service type */

	de_sgsap_imeisv,										/* 9.4.5 IMEISV */
	de_sgsap_nas_msg_container,								/* 9.4.15 NAS message container*/
	de_sgsap_mm_info,										/* 9.4.12 MM information*/

	NULL/*DE_SGSAP_UDEF_24*/,								/* Undefined */
	NULL/*DE_SGSAP_UDEF_25*/,								/* Undefined */
	NULL/*DE_SGSAP_UDEF_26*/,								/* Undefined */

	de_sgsap_err_msg,										/* 9.4.3 Erroneous message*/
	NULL/*DE_SGSAP_CLI*/,									/* 9.4.1 CLI */
	NULL/*DE_SGSAP_LCS_CLIENT_ID*/,							/* 9.4.9 LCS client identity */
	de_sgsap_lcs_indic,										/* 9.4.10 LCS indicator */
	NULL/*DE_SGSAP_SS_CODE*/,								/* 9.4.19 SS code */
	de_sgsap_serv_indic,									/* 9.4.17 Service indicator */
	NULL/*DE_SGSAP_UE_TZ*/,									/* 9.4.21b UE Time Zone */
	NULL/*DE_SGSAP_MSC_2*/,									/* 9.4.14a Mobile Station Classmark 2 */
	NULL/*DE_SGSAP_TAID*/,									/* 9.4.21a Tracking Area Identity */
	de_sgsap_ecgi,											/* 9.4.3a E-UTRAN Cell Global Identity */
	de_sgsap_ue_emm_mode		,							/* 9.4.21c UE EMM mode*/

	NULL,	/* NONE */
};

/* MESSAGE FUNCTIONS */

/*
 * 8.1	SGsAP-ALERT-ACK message
 */
static void
sgsap_alert_ack(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* IMSI	IMSI 9.4.6	M	TLV	6-10 */
	ELEM_MAND_TLV(0x01, GSM_A_PDU_TYPE_BSSMAP, BE_IMSI, NULL);

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * 8.2	SGsAP-ALERT-REJECT message
 */
static void
sgsap_alert_rej(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* IMSI	IMSI 9.4.6	M	TLV	6-10 */
	ELEM_MAND_TLV(0x01, GSM_A_PDU_TYPE_BSSMAP, BE_IMSI, NULL);
	/* SGs Cause	SGs cause  9.4.18	M	TLV	3 */
	ELEM_MAND_TLV(0x08, SGSAP_PDU_TYPE, DE_SGSAP_SGS_CAUSE, NULL);

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * 8.3	SGsAP-ALERT-REQUEST message
 */
static void
sgsap_alert_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* IMSI	IMSI 9.4.6	M	TLV	6-10 */
	ELEM_MAND_TLV(0x01, GSM_A_PDU_TYPE_BSSMAP, BE_IMSI, NULL);

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * 8.4	SGsAP-DOWNLINK-UNITDATA message
 */
static void
sgsap_dl_unitdata(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;


	/* IMSI	IMSI 9.4.6	M	TLV	6-10 */
	ELEM_MAND_TLV(0x01, GSM_A_PDU_TYPE_BSSMAP, BE_IMSI, NULL);
	/* NAS message container	NAS message container 9.4.15	M	TLV	4-253 */
	ELEM_MAND_TLV(0x16, SGSAP_PDU_TYPE, DE_SGSAP_NAS_MSG_CONTAINER, NULL);

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * 8.5	SGsAP-EPS-DETACH-ACK message
 */

static void
sgsap_eps_det_ack(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* IMSI	IMSI 9.4.6	M	TLV	6-10 */
	ELEM_MAND_TLV(0x01, GSM_A_PDU_TYPE_BSSMAP, BE_IMSI, NULL);

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}
/*
 * 8.6	SGsAP-EPS-DETACH-INDICATION message
 */

static void
sgsap_eps_det_ind(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* IMSI	IMSI 9.4.6	M	TLV	6-10 */
	ELEM_MAND_TLV(0x01, GSM_A_PDU_TYPE_BSSMAP, BE_IMSI, NULL);
	/* MME name	MME name 9.4.13	M	TLV	57 */
	ELEM_MAND_TLV(0x09, SGSAP_PDU_TYPE, DE_SGSAP_MME_NAME, NULL);
	/* IMSI detach from EPS service type	IMSI detach from EPS service type 9.4.7	M	TLV	3 */
	ELEM_MAND_TLV(0x10, SGSAP_PDU_TYPE, DE_SGSAP_IMSI_DET_EPS, NULL);

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * 8.7	SGsAP-IMSI-DETACH-ACK message
 */
static void
sgsap_imsi_det_ack(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* IMSI	IMSI 9.4.6	M	TLV	6-10 */
	ELEM_MAND_TLV(0x01, GSM_A_PDU_TYPE_BSSMAP, BE_IMSI, NULL);

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}
/*
 * 8.8	SGsAP-IMSI-DETACH-INDICATION message
 */
static void
sgsap_imsi_det_ind(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* IMSI	IMSI 9.4.6	M	TLV	6-10 */
	ELEM_MAND_TLV(0x01, GSM_A_PDU_TYPE_BSSMAP, BE_IMSI, NULL);
	/* MME name	MME name 9.4.13	M	TLV	57 */
	ELEM_MAND_TLV(0x09, SGSAP_PDU_TYPE, DE_SGSAP_MME_NAME, NULL);
	/* IMSI Detach from non-EPS service type	IMSI detach from non-EPS service type 9.4.8	M	TLV	3 */
	ELEM_MAND_TLV(0x11, SGSAP_PDU_TYPE, DE_SGSAP_IMSI_DET_NON_EPS, NULL);

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * 8.9	SGsAP-LOCATION-UPDATE-ACCEPT message
 */
static void
sgsap_imsi_loc_update_acc(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* IMSI	IMSI 9.4.6	M	TLV	6-10 */
	ELEM_MAND_TLV(0x01, GSM_A_PDU_TYPE_BSSMAP, BE_IMSI, NULL);
	/* Location area identifier	Location area identifier 9.4.11	M	TLV	7 */
	ELEM_MAND_TLV(0x04, GSM_A_PDU_TYPE_COMMON, DE_LAI, NULL);
	/* New TMSI, or IMSI	Mobile identity 9.4.14	O	TLV	6-10 */
	ELEM_OPT_TLV(0x0e,GSM_A_PDU_TYPE_COMMON, DE_MID, " - New TMSI, or IMSI");

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * 8.10	SGsAP-LOCATION-UPDATE-REJECT message
 */
static void
sgsap_imsi_loc_update_rej(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* IMSI	IMSI 9.4.6	M	TLV	6-10 */
	ELEM_MAND_TLV(0x01, GSM_A_PDU_TYPE_BSSMAP, BE_IMSI, NULL);
	/* Reject cause	Reject cause 9.4.16	M	TLV	3 */
	ELEM_MAND_TLV(0x0f,GSM_A_PDU_TYPE_DTAP, DE_REJ_CAUSE, NULL);
	/* Location area identifier	Location area identifier 9.4.11	O	TLV	7 */
	ELEM_OPT_TLV(0x04, GSM_A_PDU_TYPE_COMMON, DE_LAI, NULL);

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * 8.11	SGsAP-LOCATION-UPDATE-REQUEST message
 */

static void
sgsap_imsi_loc_update_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* IMSI	IMSI 9.4.6	M	TLV	6-10 */
	ELEM_MAND_TLV(0x01, GSM_A_PDU_TYPE_BSSMAP, BE_IMSI, NULL);
	/* MME name	MME name 9.4.13	M	TLV	57 */
	ELEM_MAND_TLV(0x09, SGSAP_PDU_TYPE, DE_SGSAP_MME_NAME, NULL);
	/* EPS location update type	EPS location update type 9.4.2	M	TLV	3 */
	ELEM_MAND_TLV(0x0a, SGSAP_PDU_TYPE, DE_SGSAP_EPS_LOC_UPD_TYPE, NULL);
	/* New location area identifier	Location area identifier 9.4.11	M	TLV	7 */
	ELEM_MAND_TLV(0x04, GSM_A_PDU_TYPE_COMMON, DE_LAI, NULL);
	/* Old location area identifier	Location area identifier 9.4.11	O	TLV	7 */
	ELEM_OPT_TLV(0x04, GSM_A_PDU_TYPE_COMMON, DE_LAI, " - Old location area identifier");
	/* TMSI status	TMSI status 9.4.21	O	TLV	3 */
	ELEM_OPT_TLV( 0x07 , GSM_A_PDU_TYPE_GM, DE_TMSI_STAT , NULL );
	/* IMEISV	IMEISV 9.4.5	O	TLV	10 */
	ELEM_OPT_TLV(0x15, SGSAP_PDU_TYPE, DE_SGSAP_IMEISV, NULL);

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * 8.12	SGsAP-MM-INFORMATION-REQUEST
 */
static void
sgsap_mm_info_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* IMSI	IMSI 9.4.6	M	TLV	6-10 */
	ELEM_MAND_TLV(0x01, GSM_A_PDU_TYPE_BSSMAP, BE_IMSI, NULL);
	/* MM information	MM information 9.4.12	M	TLV	3-n */
	ELEM_MAND_TLV(0x17, SGSAP_PDU_TYPE, DE_SGSAP_MM_INFO, NULL);

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * 8.13	SGsAP-PAGING-REJECT message
 */
static void
sgsap_paging_rej(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* IMSI	IMSI 9.4.6	M	TLV	6-10 */
	ELEM_MAND_TLV(0x01, GSM_A_PDU_TYPE_BSSMAP, BE_IMSI, NULL);
	/* SGs Cause	SGs Cause 9.4.18	M	TLV	3 */
	ELEM_MAND_TLV(0x08, SGSAP_PDU_TYPE, DE_SGSAP_SGS_CAUSE, NULL);

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}
/*
 * 8.14	SGsAP-PAGING-REQUEST message
 */
static void
sgsap_paging_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* IMSI	IMSI 9.4.6	M	TLV	6-10 */
	ELEM_MAND_TLV(0x01, GSM_A_PDU_TYPE_BSSMAP, BE_IMSI, NULL);
	/* VLR name	VLR name 9.4.22	M	TLV	3-n */
	ELEM_MAND_TLV(0x02, SGSAP_PDU_TYPE, DE_SGSAP_VLR_NAME, NULL);
	/* Service indicator	Service indicator 9.4.17	M	TLV	3 */
	ELEM_MAND_TLV(0x20, SGSAP_PDU_TYPE, DE_SGSAP_SERV_INDIC, NULL);
	/* TMSI	TMSI 9.4.20	O	TLV	6 */
	ELEM_OPT_TLV(0x03, GSM_A_PDU_TYPE_BSSMAP, BE_TMSI, NULL);
	/* CLI	CLI 9.4.1	O	TLV	3-14 */
	ELEM_OPT_TLV(0x1c, GSM_A_PDU_TYPE_DTAP, DE_CLG_PARTY_BCD_NUM, " - CLI");
	/* Location area identifier	Location area identifier 9.4.11	O	TLV	7 */
	ELEM_OPT_TLV(0x04, GSM_A_PDU_TYPE_COMMON, DE_LAI, NULL);
	/* Global CN-Id	Global CN-Id 9.4.4	O	TLV	7 */
	ELEM_OPT_TLV(0x0b, SGSAP_PDU_TYPE, DE_SGSAP_GLOBAL_CN_ID, NULL);
	/* SS code	SS code 9.4.19	O	TLV	3 */
	ELEM_OPT_TLV(0x1f, NAS_PDU_TYPE_EMM, DE_EMM_SS_CODE, NULL);
	/* LCS indicator	LCS indicator 9.4.10	O	TLV	3 */
	ELEM_OPT_TLV(0x1e, SGSAP_PDU_TYPE, DE_SGSAP_LCS_INDIC, NULL);
	/* LCS client identity	LCS client identity 9.4.9	O	TLV	3-n */
	ELEM_OPT_TLV(0x1d, NAS_PDU_TYPE_EMM, DE_EMM_LCS_CLIENT_ID, NULL);
	/* Channel needed	Channel needed 9.4.23	O	TLV	3 */
	ELEM_OPT_TLV(0x05, GSM_A_PDU_TYPE_BSSMAP, BE_CHAN_NEEDED, NULL);
	/* eMLPP Priority	eMLPP Priority 9.4.24	O	TLV	3 */
	ELEM_OPT_TLV(0x06, GSM_A_PDU_TYPE_BSSMAP, BE_EMLPP_PRIO, NULL);

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}
/*
 * 8.15	SGsAP-RESET-ACK message
 */
static void
sgsap_reset_ack(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* MME name	MME name 9.4.13	C	TLV	57 */
	ELEM_OPT_TLV(0x09, SGSAP_PDU_TYPE, DE_SGSAP_MME_NAME, NULL);
	/* VLR name	VLR name 9.4.22	C	TLV	3-n */
	ELEM_OPT_TLV(0x02, SGSAP_PDU_TYPE, DE_SGSAP_VLR_NAME, NULL);

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * 8.16	SGsAP-RESET-INDICATION message
 */
static void
sgsap_reset_ind(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* MME name	MME name 9.4.13	C	TLV	57 */
	ELEM_OPT_TLV(0x09, SGSAP_PDU_TYPE, DE_SGSAP_MME_NAME, NULL);
	/* VLR name	VLR name 9.4.22	C	TLV	3-n */
	ELEM_OPT_TLV(0x02, SGSAP_PDU_TYPE, DE_SGSAP_VLR_NAME, NULL);

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}
/*
 * 8.17	SGsAP-SERVICE-REQUEST message
 */
static void
sgsap_service_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/*IMSI	IMSI 9.4.6	M	TLV	6-10 */
	ELEM_MAND_TLV(0x01, GSM_A_PDU_TYPE_BSSMAP, BE_IMSI, NULL);
	/* Service indicator	Service indicator 9.4.17	M	TLV	3 */
	ELEM_MAND_TLV(0x20, SGSAP_PDU_TYPE, DE_SGSAP_SERV_INDIC, NULL);
	/* IMEISV	IMEISV 9.4.5	O	TLV	10 */
	ELEM_OPT_TLV(0x15, SGSAP_PDU_TYPE, DE_SGSAP_IMEISV, NULL);
	/* UE Time Zone	UE Time Zone 9.4.21b	O	TLV	3 */
	ELEM_OPT_TLV(0x21, GSM_A_PDU_TYPE_DTAP, DE_TIME_ZONE, " - UE Time Zone");
	/* Mobile Station Classmark 2	Mobile Station Classmark 2 9.4.14a	O	TLV	5 */
	ELEM_OPT_TLV(0x22 ,GSM_A_PDU_TYPE_COMMON, DE_MS_CM_2, NULL);
	/* TAI	Tracking Area Identity 9.4.21a	O	TLV	7 */
	ELEM_OPT_TLV(0x23, NAS_PDU_TYPE_EMM, DE_EMM_TRAC_AREA_ID, NULL);
	/* E-CGI	E-UTRAN Cell Global Identity 9.4.3a	O	TLV	9 */
	ELEM_OPT_TLV(0x24, SGSAP_PDU_TYPE, DE_SGSAP_ECGI, NULL);
	/* UE EMM Mode	UE EMM mode 9.4.21c	O	TLV	3 */
	ELEM_OPT_TLV(0x25, SGSAP_PDU_TYPE, DE_SGSAP_UE_EMM_MODE, NULL);

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * 8.18	SGsAP-STATUS message
 */
static void
sgsap_status(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* IMSI	IMSI 9.4.6	O	TLV	6-10 */
	ELEM_OPT_TLV(0x01, GSM_A_PDU_TYPE_BSSMAP, BE_IMSI, NULL);
	/* SGs cause	SGs cause 9.4.18	M	TLV	3 */
	ELEM_MAND_TLV(0x08, SGSAP_PDU_TYPE, DE_SGSAP_SGS_CAUSE, NULL);
	/* Erroneous message	Erroneous message 9.4.3	M	TLV	3-n */
	ELEM_OPT_TLV(0x1e, SGSAP_PDU_TYPE, DE_SGSAP_ERR_MSG, NULL);

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * 8.19	SGsAP-TMSI-REALLOCATION-COMPLETE message
 */
static void
sgsap_tmsi_realloc_comp(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/*IMSI	IMSI 9.4.6	M	TLV	6-10  */
	ELEM_MAND_TLV(0x01, GSM_A_PDU_TYPE_BSSMAP, BE_IMSI, NULL);

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * 8.20	SGsAP-UE-ACTIVITY-INDICATION message
 */
static void
sgsap_ue_act_ind(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* IMSI	IMSI 9.4.6	M	TLV	6-10 */
	ELEM_MAND_TLV(0x01, GSM_A_PDU_TYPE_BSSMAP, BE_IMSI, NULL);

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * 8.21	SGsAP-UE-UNREACHABLE message
 */
static void
sgsap_ue_unreachable(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;


	/* IMSI	IMSI 9.4.6	M	TLV	6-10 */
	ELEM_MAND_TLV(0x01, GSM_A_PDU_TYPE_BSSMAP, BE_IMSI, NULL);
	/* SGs cause	SGs cause 9.4.18	M	TLV	3 */
	ELEM_MAND_TLV(0x08, SGSAP_PDU_TYPE, DE_SGSAP_SGS_CAUSE, NULL);

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}
/*
 * 8.22	SGsAP-UPLINK-UNITDATA message
 */
static void
sgsap_ue_ul_unitdata(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* IMSI	IMSI 9.4.6	M	TLV	6-10 */
	ELEM_MAND_TLV(0x01, GSM_A_PDU_TYPE_BSSMAP, BE_IMSI, NULL);
	/* NAS message container	NAS message container 9.4.15	M	TLV	4-253 */
	ELEM_MAND_TLV(0x16, SGSAP_PDU_TYPE, DE_SGSAP_NAS_MSG_CONTAINER, NULL);
	/* IMEISV	IMEISV 9.4.5	O	TLV	10 */
	ELEM_OPT_TLV(0x15, SGSAP_PDU_TYPE, DE_SGSAP_IMEISV, NULL);
	/* UE Time Zone	UE Time Zone 9.4.21b	O	TLV	3 */
	ELEM_OPT_TLV(0x21, GSM_A_PDU_TYPE_DTAP, DE_TIME_ZONE, " - UE Time Zone");
	/* Mobile Station Classmark 2	Mobile Station Classmark 2 9.4.14a	O	TLV	5 */
	ELEM_OPT_TLV(0x22 ,GSM_A_PDU_TYPE_COMMON, DE_MS_CM_2, NULL);
	/* TAI	Tracking Area Identity 9.4.21a	O	TLV	7 */
	ELEM_OPT_TLV(0x23, NAS_PDU_TYPE_EMM, DE_EMM_TRAC_AREA_ID, NULL);
	/* E-CGI	E-UTRAN Cell Global Identity 9.4.3a	O	TLV	9 */
	ELEM_OPT_TLV(0x24, SGSAP_PDU_TYPE, DE_SGSAP_ECGI, NULL);

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}
/*
 * 8.23	SGsAP-RELEASE-REQUEST message
 */
static void
sgsap_release_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* IMSI	IMSI 9.4.6	M	TLV	6-10 */
	ELEM_MAND_TLV(0x01, GSM_A_PDU_TYPE_BSSMAP, BE_IMSI, NULL);
	/* SGs cause	SGs cause 9.4.18	O	TLV	3 */
	ELEM_MAND_TLV(0x08, SGSAP_PDU_TYPE, DE_SGSAP_SGS_CAUSE, NULL);

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * 8.24	SGsAP-SERVICE-ABORT-REQUEST message
 */
/* No IE's */

/*
 * 9.2	Message type
 */
static const value_string sgsap_msg_strings[] = {
	{ 0x01,	"SGsAP-PAGING-REQUEST"},		/* 	8.14 */
	{ 0x02,	"SGsAP-PAGING-REJECT"},			/* 	8.13 */
/*
 * 0 0 0 0 0 0 1 1
 * to
 * 0 0 0 0 0 1 0 1
 * Unassigned: treated as an unknown Message type
 */
	{ 0x03,	"Unassigned"},							/* 7 */
	{ 0x04,	"Unassigned"},							/* 7 */
	{ 0x05,	"Unassigned"},							/* 7 */

	{ 0x06,	"SGsAP-SERVICE-REQUEST"},				/* 8.17 */
	{ 0x07,	"SGsAP-DOWNLINK-UNITDATA"},				/* 8.4 */
	{ 0x08,	"SGsAP-UPLINK-UNITDATA"},				/* 8.22 */
	{ 0x09,	"SGsAP-LOCATION-UPDATE-REQUEST"},		/* 8.11 */
	{ 0x0a,	"SGsAP-LOCATION-UPDATE-ACCEPT"},		/* 8.9 */
	{ 0x0b,	"SGsAP-LOCATION-UPDATE-REJECT"},		/* 8.10 */
	{ 0x0c,	"SGsAP-TMSI-REALLOCATION-COMPLETE"},	/* 8.19 */
	{ 0x0d,	"SGsAP-ALERT-REQUEST"},					/* 8.3 */
	{ 0x0e,	"SGsAP-ALERT-ACK"},						/* 8.1 */
	{ 0x0f,	"SGsAP-ALERT-REJECT"},					/* 8.2 */
	{ 0x10,	"SGsAP-UE-ACTIVITY-INDICATION"},		/* 8.20 */
	{ 0x11,	"SGsAP-EPS-DETACH-INDICATION"},			/* 8.6 */
	{ 0x12,	"SGsAP-EPS-DETACH-ACK"},				/* 8.5 */
	{ 0x13,	"SGsAP-IMSI-DETACH-INDICATION"},		/* 8.8 */
	{ 0x14,	"SGsAP-IMSI-DETACH-ACK"},				/* 8.7 */
	{ 0x15,	"SGsAP-RESET-INDICATION"},				/* 8.16 */
	{ 0x16,	"SGsAP-RESET-ACK"},						/* 8.15 */
	{ 0x17,	"SGsAP-SERVICE-ABORT-REQUEST"},			/* 8.24 */
/*
 * 0 0 0 1 1 0 0 0
 * to
 * 0 0 0 1 1 0 0 1
 * Unassigned: treated as an unknown Message type
 */
 	{ 0x18,	"Unassigned"},
 	{ 0x19,	"Unassigned"},

	{ 0x1a,	"SGsAP-MM-INFORMATION-REQUEST"},		/* 8.12 */
	{ 0x1b,	"SGsAP-RELEASE-REQUEST"},				/* 8.23 */
/*
 * 0 0 0 1 1 1 0 0	Unassigned: treated as an unknown Message type	7
 */
	{ 0x1c,	"Unassigned"},			/* 8.12 */

	{ 0x1d,	"SGsAP-STATUS"},			/* 8.18 */
	{ 0x1e,	"Unassigned"},
	{ 0x1f,	"SGsAP-UE-UNREACHABLE"},			/* 8.21 */
	{ 0,	NULL }
};
static value_string_ext sgsap_msg_strings_ext = VALUE_STRING_EXT_INIT(sgsap_msg_strings);

#define	NUM_SGSAP_MSG (sizeof(sgsap_msg_strings)/sizeof(value_string))
static gint ett_sgsap_msg[NUM_SGSAP_MSG];
static void (*sgsap_msg_fcn[])(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len) = {
	sgsap_paging_req,			/* 0x01,	"SGsAP-PAGING-REQUEST"	8.14 */
	sgsap_paging_rej,			/* 0x02,	"SGsAP-PAGING-REJECT"	8.13 */
/*
 * 0 0 0 0 0 0 1 1
 * to
 * 0 0 0 0 0 1 0 1
 * Unassigned: treated as an unknown Message type
 */
	NULL,							/* 0x03,	"Unassigned" 7 */
	NULL,							/* 0x04,	"Unassigned" 7 */
	NULL,							/* 0x05,	"Unassigned" 7 */

	sgsap_service_req,				/* 0x06,	"SGsAP-SERVICE-REQUEST" 8.17 */
	sgsap_dl_unitdata,				/* 0x07,	"SGsAP-DOWNLINK-UNITDATA" 8.4 */
	sgsap_ue_ul_unitdata,			/* 0x08,	"SGsAP-UPLINK-UNITDATA" 8.22 */
	sgsap_imsi_loc_update_req,		/* 0x09,	"SGsAP-LOCATION-UPDATE-REQUEST" 8.11 */
	sgsap_imsi_loc_update_acc,		/* 0x0a,	"SGsAP-LOCATION-UPDATE-ACCEPT" 8.9 */
	sgsap_imsi_loc_update_rej,		/* 0x0b,	"SGsAP-LOCATION-UPDATE-REJECT" 8.10 */
	sgsap_tmsi_realloc_comp,		/* 0x0c,	"SGsAP-TMSI-REALLOCATION-COMPLETE"  8.19 */
	sgsap_alert_req,				/* 0x0d,	"SGsAP-ALERT-REQUEST" 8.3 */
	sgsap_alert_ack,				/* 0x0e,	"SGsAP-ALERT-ACK" 8.1 */
	sgsap_alert_rej,				/* 0x0f,	"SGsAP-ALERT-REJECT" 8.2 */
	sgsap_ue_act_ind,				/* 0x10,	"SGsAP-UE-ACTIVITY-INDICATION" 8.20 */
	sgsap_eps_det_ind,				/* 0x11,	"SGsAP-EPS-DETACH-INDICATION" 8.6 */
	sgsap_eps_det_ack,				/* 0x12,	"SGsAP-EPS-DETACH-ACK" 8.5 */
	sgsap_imsi_det_ind,				/* 0x13,	"SGsAP-IMSI-DETACH-INDICATION" 8.8 */
	sgsap_imsi_det_ack,				/* 0x14,	"SGsAP-IMSI-DETACH-ACK" 8.7 */
	sgsap_reset_ind,				/* 0x15,	"SGsAP-RESET-INDICATION" 8.16 */
	sgsap_reset_ack,				/* 0x16,	"SGsAP-RESET-ACK" 8.15 */
	NULL,/* No IE's */				/* 0x17,	"SGsAP-SERVICE-ABORT-REQUEST" 8.24 */
/*
 * 0 0 0 1 1 0 0 0
 * to
 * 0 0 0 1 1 0 0 1
 * Unassigned: treated as an unknown Message type
 */
 	NULL,							/* 0x18,	"Unassigned" */
 	NULL,							/* 0x19,	"Unassigned" */

	sgsap_mm_info_req,				/* 0x1a,	"SGsAP-MM-INFORMATION-REQUEST" 8.12 */
	sgsap_release_req,				/* 0x1b,	"SGsAP-RELEASE-REQUEST" 8.23 */
/*
 * 0 0 0 1 1 1 0 0	Unassigned: treated as an unknown Message type	7
 */
	NULL,							/* 0x1c,	"Unassigned" */

	sgsap_status,					/* 0x1d,	"SGsAP-STATUS" 8.18 */
	NULL,							/* 0x1e,	"Unassigned" */
	sgsap_ue_unreachable,			/* 0x1f,	"SGsAP-UE-UNREACHABLE" 8.21 */

	NULL,	/* NONE */
};

static void get_sgsap_msg_params(guint8 oct, const gchar **msg_str, int *ett_tree, int *hf_idx, msg_fcn *msg_fcn)
{
	gint			idx;

	*msg_str = match_strval_idx_ext((guint32) (oct & 0xff), &sgsap_msg_strings_ext, &idx);
	*ett_tree = ett_sgsap_msg[idx];
	*hf_idx = hf_sgsap_msg_type;
	*msg_fcn = sgsap_msg_fcn[idx];

	return;
}


static void
dissect_sgsap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item		*item;
	proto_tree		*sgsap_tree;
	int				offset = 0;
	guint32			len;
	const gchar		*msg_str;
	gint			ett_tree;
	int				hf_idx;
	void			(*msg_fcn)(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len);
	guint8			oct;

	/* Save pinfo */
	gpinfo = pinfo;
	len = tvb_length(tvb);

	/* Make entry in the Protocol column on summary display */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, PSNAME);

	item = proto_tree_add_item(tree, proto_sgsap, tvb, 0, -1, ENC_NA);
	sgsap_tree = proto_item_add_subtree(item, ett_sgsap);

	/* Messge type IE*/
	oct = tvb_get_guint8(tvb,offset);
	msg_fcn = NULL;
	ett_tree = -1;
	hf_idx = -1;
	msg_str = NULL;

	get_sgsap_msg_params(oct, &msg_str, &ett_tree, &hf_idx, &msg_fcn);

	if(msg_str){
		col_add_fstr(pinfo->cinfo, COL_INFO, "%s", msg_str);
	}else{
		proto_tree_add_text(tree, tvb, offset, 1,"Unknown message 0x%x",oct);
		return;
	}

	/*
	 * Add SGSAP message name
	 */
	proto_tree_add_item(sgsap_tree, hf_idx, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;


	/*
	 * decode elements
	 */
	if (msg_fcn == NULL)
	{
		proto_tree_add_text(sgsap_tree, tvb, offset, len - offset,
			"Message Elements");
	}
	else
	{
		(*msg_fcn)(tvb, sgsap_tree, pinfo, offset, len - offset);
	}

}



void proto_register_sgsap(void) {
    guint        i;
    guint        last_offset;

    /* List of fields */

  static hf_register_info hf[] = {
    { &hf_sgsap_msg_type,
        { "SGSAP Message Type",    "sgsap.msg_type",
        FT_UINT8, BASE_HEX|BASE_EXT_STRING, &sgsap_msg_strings_ext, 0x0,
        NULL, HFILL }
    },
    { &hf_sgsap_elem_id,
        { "Element ID",    "sgsap.elem_id",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_sgsap_eps_location_update_type,
        { "EPS location update type",    "sgsap.eps_location_update_type",
        FT_UINT8, BASE_DEC, VALS(sgsap_eps_location_update_type_values),0x0,
        NULL, HFILL }
    },
    { &hf_sgsap_service_indicator_value,
        { "Service indicator",    "sgsap.service_indicator",
        FT_UINT8, BASE_DEC, VALS(sgsap_service_indicator_values),0x0,
        NULL, HFILL }
    },
    { &hf_sgsap_sgs_cause,
        { "SGs cause",    "sgsap.sgs_cause",
        FT_UINT8, BASE_DEC|BASE_EXT_STRING, &sgsap_sgs_cause_values_ext,0x0,
        NULL, HFILL }
    },
    { &hf_sgsap_ue_emm_mode,
        { "UE EMM mode",    "sgsap.ue_emm_mode",
        FT_UINT8, BASE_DEC, VALS(sgsap_ue_emm_mode_values),0x0,
        NULL, HFILL }
    },
    { &hf_sgsap_eci,
        {"ECI (E-UTRAN Cell Identifier)", "sgsap.eci",
        FT_UINT32, BASE_DEC, NULL, 0x0fffffff,
        NULL, HFILL}
    },
    { &hf_sgsap_cn_id,
        {"CN_ID", "sgsap.cn_id",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_sgsap_imsi_det_eps,
        { "IMSI detach from EPS service type",    "sgsap.imsi_det_eps",
        FT_UINT8, BASE_DEC, VALS(sgsap_imsi_det_from_eps_serv_type_values),0x0,
        NULL, HFILL }
    },
    { &hf_sgsap_lcs_indic,
        { "LCS indicator",    "sgsap.lcs_indicator",
        FT_UINT8, BASE_DEC, VALS(sgsap_lcs_indic_values),0x0,
        NULL, HFILL }
    },
    { &hf_sgsap_mme_name,
        {"MME name", "sgsap.mme_name",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_sgsap_vlr_name,
        {"VLR name", "sgsap.mme_name",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL}
    },
	{ &hf_sgsap_imeisv,
        {"IMEISV", "sgsap.imeisv",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL}
    },
  };

    /* Setup protocol subtree array */
#define	NUM_INDIVIDUAL_ELEMS	1
    gint *ett[NUM_INDIVIDUAL_ELEMS +
          NUM_SGSAP_ELEM +
          NUM_SGSAP_MSG];

    ett[0] = &ett_sgsap;

    last_offset = NUM_INDIVIDUAL_ELEMS;

    for (i=0; i < NUM_SGSAP_ELEM; i++, last_offset++)
    {
        ett_sgsap_elem[i] = -1;
        ett[last_offset] = &ett_sgsap_elem[i];
    }

    for (i=0; i < NUM_SGSAP_MSG; i++, last_offset++)
    {
        ett_sgsap_msg[i] = -1;
        ett[last_offset] = &ett_sgsap_msg[i];
    }

    /* Register protocol */
    proto_sgsap = proto_register_protocol(PNAME, PSNAME, PFNAME);
    /* Register fields and subtrees */
    proto_register_field_array(proto_sgsap, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register dissector */
    register_dissector(PFNAME, dissect_sgsap, proto_sgsap);
}

void
proto_reg_handoff_sgsap(void)
{
    /* The registered SCTP port number for SGsAP is 29118.
     * The payload protocol identifier to be used for SGsAP is 0.
     */
    static gboolean Initialized=FALSE;
    static dissector_handle_t sgsap_handle;
    static guint SctpPort;

    sgsap_handle = find_dissector("sgsap");
    gsm_a_dtap_handle = find_dissector("gsm_a_dtap");

    if (!Initialized) {
        dissector_add_handle("sctp.port", sgsap_handle);   /* for "decode-as"  */
        Initialized=TRUE;
    } else {
        if (SctpPort != 0) {
            dissector_delete_uint("sctp.port", SctpPort, sgsap_handle);
        }
    }

    SctpPort=gbl_sgsapSctpPort;
    if (SctpPort != 0) {
        dissector_add_uint("sctp.port", SctpPort, sgsap_handle);
    }
}
