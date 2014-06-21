/* c-basic-offset: 2; tab-width: 2; indent-tabs-mode: t
 * vi: set shiftwidth=2 tabstop=2 noexpandtab:
 * :indentSize=2:tabSize=2:noTabs=false:
 */

/* packet-atn-ulcs.c
 * By Mathias Guettler <guettler@web.de>
 * Copyright 2013
 *
 * Routines for ATN upper layer
 * protocol packet disassembly

 * ATN upper layers are embedded within OSI Layer 4 (COTP).
 *
 * ATN upper layers contain:
 * Session Layer (NUL protocol option)
 * Presentation Layer (NUL protocol option)
 * ATN upper Layer/Application (ACSE PDU or PDV-list PDU)

 * ATN applications protocols (i.e. CM or CPDLC) are contained within
 * ACSE user-information or PDV presentation data.

 * details see:
 * http://en.wikipedia.org/wiki/CPDLC
 * http://members.optusnet.com.au/~cjr/introduction.htm

 * standards:
 * http://legacy.icao.int/anb/panels/acp/repository.cfm

 * note:
 * We are dealing with ATN/ULCS aka ICAO Doc 9705 Ed2 here
 * (don't think there is an ULCS equivalent for "FANS-1/A ").

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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*
 developper comments:
why not using existing ses, pres and acse dissectors ?
		ATN upper layers are derived from OSI standards for session,
		presentation and application but the encoding differs
		(it's PER instead of BER encoding to save bandwith).
		Session and presentation use the "null" encoding option,
		meaning that they are only present at connection establishment
		and ommitted otherwise.
		Instead of adapting existing dissectors it seemed simpler and cleaner
		to implement everything the new atn-ulcs dissector.

why using conversations ?
		PER encoded user data is ambigous; the same encoding may apply to a CM or
		CPDLC PDU. The workaround is to decode on a transport connection basis.
		I use my own version of conversations to identify
		the transport connection the PDU belongs to for the standard functions
		from "conversation.h" didn't work out.

what is the use of AARQ/AARE data ?
		Converstions should be maintained on the COTP layer in a standard way
		for there are usually more packets available than in the layers above.
		In the worst case my dissector is called from a DT packet which
		has destination references but no source reference.
		I have to guess the reference used the other way round
		(curently I am using ACSE PDU'S used during OSI connection establishment for that).
		The idea is that each ACSE AARQ is answered by ACSE AARE and having this sequence
		I have all the source/destination references for this transport connection.
		I use AARQ/AARE data to store the source/destination reference of AARQ as well
		as the optional ae-qualifier which tells me the application and
		the dissector I have to use.
		This approach donesn't work well when there are interleaving AARQ/AARE sequences for
		the same aircraft.

which ATN standard is supported ?
		The dissector has been tested with ICAO doc9705 Edition2 compliant traffic.
		No ATN Secutity is supported.
		note:
		The ATN upper layers are derived from OSI standards (ICAO DOC 9705)
		while ATN/IPS (ICAO DOC 9896) which is entirely based on IPV6.

*/

/*
 known defects/deficiencies:

-	user-information within AARE is sometines not decoded due to an unset flag
		(the field is optional). As far as I can tell asn2wrs is right here,
		but on the other hand I know that in all of this cases user-information
		is present and is processed by the ATN end system.
		Maybe a true ATN expert may help me out here.

	- The conversation handling is based on src/dst addresses as well as
		source or destination references depending on the TP4 packet type.
		This means that after some time these references get reused for
		new conversations. This almost certain happens for traces longer
		than one day rendering this dissector unsuitable for captures exceeding
		this one day.

*/

#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include <epan/dissectors/packet-ber.h>
#include <epan/dissectors/packet-per.h>
#include <epan/wmem/wmem.h>
#include <epan/address.h>
#include <epan/conversation.h>

#include <stdio.h>
#include <string.h>
#ifndef _MSC_VER
#include <stdint.h>
#endif

#include "packet-atn-ulcs.h"

#define ATN_ACSE_PROTO "ICAO Doc9705 ULCS ACSE (ISO 8649/8650-1:1996)"
#define ATN_ULCS_PROTO "ICAO Doc9705 ULCS"

void proto_register_atn_ulcs(void);
void proto_reg_handoff_atn_ulcs(void);

static heur_dissector_list_t atn_ulcs_heur_subdissector_list;

/* presentation subdissectors i.e. CM, CPDLC */
static dissector_handle_t atn_cm_handle = NULL;
static dissector_handle_t atn_cpdlc_handle = NULL;

static int proto_atn_ulcs          = -1;
static guint32 ulcs_context_value = 0;
static const char *object_identifier_id;

static wmem_tree_t *aarq_data_tree = NULL;
static wmem_tree_t *atn_conversation_tree = NULL;


static proto_tree *root_tree = NULL;

/* forward declarations for functions generated from asn1 */
static int dissect_atn_ulcs_T_externalt_encoding_single_asn1_type(
		tvbuff_t *tvb _U_,
		int offset _U_,
		asn1_ctx_t *actx _U_,
		proto_tree *tree _U_,
		int hf_index
		_U_);

static int dissect_atn_ulcs_T_externalt_encoding_octet_aligned(
		tvbuff_t *tvb _U_,
		int offset _U_,
		asn1_ctx_t *actx _U_,
		proto_tree *tree _U_,
		int hf_index _U_);

static int dissect_atn_ulcs_T_externalt_encoding_arbitrary(
		tvbuff_t *tvb _U_,
		int offset _U_,
		asn1_ctx_t *actx _U_,
		proto_tree *tree _U_,
		int hf_index _U_);

static void dissect_ACSE_apdu_PDU(
		tvbuff_t *tvb _U_,
		packet_info *pinfo _U_,
		proto_tree *tree _U_);

guint32 dissect_per_object_descriptor_t(
		tvbuff_t *tvb,
		guint32 offset,
		asn1_ctx_t *actx,
		proto_tree *tree,
		int hf_index,
		tvbuff_t **value_tvb);

static gint	dissect_atn_ulcs(
		tvbuff_t *tvb,
		packet_info *pinfo,
		proto_tree	*tree,
		void *data _U_);

#include "packet-atn-ulcs-hf.c"

#include "packet-atn-ulcs-ett.c"
static gint ett_atn_ulcs = -1;
static gint ett_atn_acse = -1;

#include "packet-atn-ulcs-fn.c"

#if 0
/* re-implementing external data: packet-per.c */
static const value_string per_External_encoding_vals[] = {
{   0, "single-ASN1-type" },
{   1, "octet-aligned" },
{   2, "arbitrary" },
{ 0, NULL }
};

/* re-implementing external data: packet-per.c */
static const per_choice_t External_encoding_choice[] =
{
		{		0,
				&hf_atn_ulcs_externalt_encoding_single_asn1_type,
				ASN1_NO_EXTENSIONS,
				dissect_atn_ulcs_T_externalt_encoding_single_asn1_type
		},
		{		1,
				&hf_atn_ulcs_externalt_encoding_octet_aligned,
				ASN1_NO_EXTENSIONS,
				dissect_atn_ulcs_T_externalt_encoding_octet_aligned
		},
		{		2,
				&hf_atn_ulcs_externalt_encoding_arbitrary,
				ASN1_NO_EXTENSIONS,
				dissect_atn_ulcs_T_externalt_encoding_arbitrary
		},
		{		0,
				NULL,
				0,
				NULL
		}
};
#endif

/* ATN Session layer */
#define SES_PDU_TYPE_MASK			0xf8
#define SES_PARAM_IND_MASK			0x04
#define SES_PARAM_B2_MASK			0x02
#define SES_PARAM_B1_MASK			0x01

static int hf_atn_ses_type = -1;
static int hf_atn_ses_param_ind = -1;
static int hf_atn_ses_param_b1 = -1;
static int hf_atn_ses_param_b2 = -1;

static gint ett_atn_ses = -1;

#define ATN_SES_PROTO "ICAO Doc9705 ULCS Session (ISO 8326/8327-1:1994)"

const value_string atn_ses_param_ind[] =
{
		{0,	"No Parameter Indication "},
		{1,	"Parameter Indication "},
		{0,	NULL }
};

const value_string srf_b2[] =
{
		{0,	"Transport Connection is kept"},
		{1,	"Transport Connection is released" },
		{0,	NULL }
};

const value_string srf_b1[] =
{
		{0,	"Transport Connection is transient"},
		{1,	"Transport Connection is persistent"},
		{0,	NULL }
};

#define SES_ATN_SCN				0xe8
#define SES_ATN_SCNC			0xf8
#define SES_ATN_SAC				0xf0
#define SES_ATN_SACC			0xd8
#define SES_ATN_SRF				0xe0
#define SES_ATN_SRFC			0xa0

const value_string atn_ses_type[] =
{
		{ 0x1d,	"Short Connect (SCN) SPDU" },
		{ 0x1f,	"Short Connect Accept (SAC) SPDU" },
		{ 0x1e,	"Short Connect Accept Continue (SACC) SPDU" },
		{ 0x1c,	"Short Refuse (SRF) SPDU" },
		{ 0x14,	"Short Refuse Continue (SRFC) SPDU" },
		{0,	NULL }
};

/* ATN Presentation layer */
#define ATN_PRES_PROTO "ICAO Doc9705 ULCS Presentation (ISO 8822/8823-1:1994)"

static int hf_atn_pres_err	 = -1;
static gint ett_atn_pres		= -1;

#define ATN_SES_PRES_MASK 0xf803
#define PRES_CPR_ER_MASK		0x70

/* type determined by SPDU and PPDU */
const value_string atn_pres_vals[] =
{
		{ 0xe802, "Short Presentation Connect PPDU (CP) " },
		{ 0xf802, "Short Presentation Connect PPDU (CP) " },
		{ 0xf002, "Short Presentation Connect Accept PPDU (CPA)" },
		{ 0xd802, "Short Presentation Connect Accept PPDU (CPA)" },
		{ 0xe002, "Short Presentation Connect Reject PPDU (CPR)" },
		{ 0xa002, "Short Presentation Connect Reject PPDU (CPR)" },
		{0,					NULL }
};

/* Short Presentation Connect Reject PPDU's 0yyy 00zz */
const value_string atn_pres_err[] =
{
		{ 0x00, "Presentation-user" },
		{ 0x01, "Reason not specified (transient)"},
		{ 0x02,	"Temporary congestion (transient)"},
		{ 0x03,	"Local limit exceeded (transient)"},
		{ 0x04, "Called presentation-address unknown (permanent)"},
		{ 0x05,	"Protocol version not supported (permanent)"},
		{ 0x06,	"Default context not supported (permanent)"},
		{ 0x07,	"User data not readable (permanent)"},
		{ 0,					NULL }
};

#if 0
/* re-implementing external data: packet-per.c */
static int	atn_ulcs_Externalt_encoding(
		tvbuff_t *tvb _U_,
		int offset _U_,
		asn1_ctx_t *actx _U_,
		proto_tree *tree _U_,
		int hf_index _U_)
{
		offset = dissect_per_choice(
				tvb,
				offset,
				actx,
				tree,
				hf_index,
				ett_atn_ulcs_EXTERNALt,
				External_encoding_choice,
				&actx->external.encoding);

		return offset;
}

/* re-implementing external data: packet-per.c */
static guint32	atn_per_external_type(
		tvbuff_t *tvb _U_,
		guint32 offset,
		asn1_ctx_t *actx,
		proto_tree *tree _U_,
		int hf_index _U_,
		per_type_fn type_cb)
{
		memset(&actx->external, '\0', sizeof(actx->external));
		actx->external.hf_index = -1;
		actx->external.encoding = -1;

		actx->external.u.per.type_cb = type_cb;
		offset = atn_ulcs_Externalt_encoding(
				tvb,
				offset,
				actx,
				tree,
				hf_index);

		memset(
				&actx->external,
				'\0',
				sizeof(actx->external));

		actx->external.hf_index = -1;
		actx->external.encoding = -1;

		return offset;
}
#endif

/* determine 24-bit aircraft address(ARS) */
/* from 20-byte ATN NSAP. */
guint32 get_aircraft_24_bit_address_from_nsap(
		packet_info *pinfo)
{
		const guint8* addr = NULL;
		guint32 ars =0;
		guint32 adr_prefix =0;

		/* check NSAP address type*/
		if( (pinfo->src.type != AT_OSI) ||
				(pinfo->dst.type != AT_OSI)) {
				return ars; }

		/* 20 octets address length required */
		/* for ATN */
		if( (pinfo->src.len != 20) ||
				(pinfo->dst.len != 20)) {
				return ars; }

		/* first try source address */
		/* if the src address originates */
		/* from an aircraft it's downlink */

		/* convert addr into 32-bit integer */
		addr = (const guint8 *)pinfo->src.data;
		adr_prefix =
				((addr[0]<<24) |
				(addr[1]<<16) |
				(addr[2]<<8) |
				addr[3] );

		/* according to ICAO doc9507 Ed2 SV5  */
		/* clause 5.4.3.8.1.5 and  5.4.3.8.1.3 */
		/* mobile addresses contain "c1" of "41" */
		/* in the VER subfield of the NSAP */
		if((adr_prefix == 0x470027c1) ||
				(adr_prefix == 0x47002741)) {
			/* ICAO doc9507 Ed2 SV5 5.4.3.8.4.4 */
			/* states that the ARS subfield containes */
			/* the  24-bitaddress of the aircraft */
				ars = ((addr[8])<<16) |
						((addr[9])<<8) |
						(addr[10]);
		}

		/* try destination address */
		/* if the src address originates */
		/* from an aircraft it's downlink */

		/* convert addr into 32-bit integer */
		addr = (const guint8 *)pinfo->dst.data;
		adr_prefix = ((addr[0]<<24) |
				(addr[1]<<16) |
				(addr[2]<<8) |
				addr[3] );

		/* according to ICAO doc9507 Ed2 SV5  */
		/* clause 5.4.3.8.1.5 and  5.4.3.8.1.3 */
		/* mobile addresses contain "c1" of "41" */
		/* in the VER subfield of the NSAP */
		if((adr_prefix == 0x470027c1) ||
				(adr_prefix == 0x47002741)) {
			/* ICAO doc9507 Ed2 SV5 5.4.3.8.4.4 */
			/* states that the ARS subfield containes */
			/* the  24-bitaddress of the aircraft */
			ars = ((addr[8])<<16) |
						((addr[9])<<8) |
						(addr[10]);
		}
		return ars;
}

/* determine whether a PDU is uplink or downlink */
/* by checking for known aircraft  address prefices*/
int check_heur_msg_type(packet_info *pinfo  _U_)
{
		int t = no_msg;
		const guint8* addr = NULL;
		guint32 adr_prefix =0;

		/* check NSAP address type*/
		if( (pinfo->src.type != AT_OSI) || (pinfo->dst.type != AT_OSI)) {
				return t; }

		/* check NSAP address length; 20 octets address length required */
		if( (pinfo->src.len != 20) || (pinfo->dst.len != 20)) {
				return t; }

		addr = (const guint8 *)pinfo->src.data;

		/* convert address to 32-bit integer  */
		adr_prefix = ((addr[0]<<24) | (addr[1]<<16) | (addr[2]<<8) | addr[3] );

		/* According to the published ATN NSAP adddressing scheme */
		/* in ICAO doc9705 Ed2 SV5 5.4.3.8.1.3 and 5.4.3.8.1.5  */
		/* the "VER" field shall be 0x41 ("all Mobile AINSC") or */
		/* 0xc1 ("all Mobile ATSC") for mobile stations (aka aircraft).*/
		if((adr_prefix == 0x470027c1) || (adr_prefix == 0x47002741)) {
				t = dm; /* source is an aircraft: it's a downlink PDU */
		}

		addr = (const guint8 *)pinfo->dst.data;

		/* convert address to 32-bit integer  */
		adr_prefix = ((addr[0]<<24) | (addr[1]<<16) | (addr[2]<<8) | addr[3] );

		/* According to the published ATN NSAP adddressing scheme */
		/* in ICAO doc9705 Ed2 SV5 5.4.3.8.1.3 and 5.4.3.8.1.5  */
		/* the "VER" field shall be 0x41 ("all Mobile AINSC") or */
		/* 0xc1 ("all Mobile ATSC") for mobile stations (aka aircraft).*/
		if((adr_prefix == 0x470027c1) || (adr_prefix == 0x47002741)) {
				t = um; /* destination is aircraft: uplink PDU */
		}

		return t;
}

/* conversation may be used by other dissectors  */
wmem_tree_t *get_atn_conversation_tree(void){
		return atn_conversation_tree;
}


/* find a atn conversation tree node by an endpoint  */
/* an endpoint is identified by atn src and dst addresses */
/* and srcref or dstref (depends on the transport packet type) */
/* IMHO it's a hack - conversations should be maintained */
/* at transport layer (cotp) but this isn't working yet. */
atn_conversation_t * find_atn_conversation(
		address *address1,
		guint16 clnp_ref1,
		address *address2 )
{
		atn_conversation_t *cv = NULL;
		guint32	key = 0;
		guint32	tmp = 0;

		ADD_ADDRESS_TO_HASH( tmp, address1);
		key = (tmp << 16) | clnp_ref1 ;

		ADD_ADDRESS_TO_HASH( tmp, address2);
		key = (tmp << 24) | key ;

		/* search for atn conversation */
		cv = (atn_conversation_t *)
				wmem_tree_lookup32(get_atn_conversation_tree(),key);

		return cv;
}

/* create a atn conversation tree node  */
/* conversation data is to be allocated externally */
/* a conversation may be referenced from both endpoints */
atn_conversation_t * create_atn_conversation(
		address *address1,
		guint16 clnp_ref1,
		address *address2,
		atn_conversation_t *conversation)
{
		atn_conversation_t *cv = NULL;
		guint32	key = 0;
		guint32	tmp = 0;

		ADD_ADDRESS_TO_HASH( tmp, address1);
		key = (tmp << 16) | clnp_ref1 ;

		ADD_ADDRESS_TO_HASH( tmp, address2);
		key = (tmp << 24) | key ;

		/* search for aircraft entry */
		cv = (atn_conversation_t *)
		wmem_tree_lookup32(
				get_atn_conversation_tree(),
				key);

		/* tree node  already present  */
		if(cv) {
			return NULL; }

		/* insert conversation data in tree*/
		wmem_tree_insert32(
				get_atn_conversation_tree(),
				key,
				(void*)conversation);

		return conversation;
}

static int
dissect_atn_ulcs(
		tvbuff_t *tvb,
		packet_info *pinfo,
		proto_tree *tree,
		void *data _U_)
{
		int offset = 0;
		proto_item *ti = NULL;
		proto_tree *atn_ulcs_tree = NULL;
		guint8 value_pres = 0;
		guint8 value_ses = 0;
		guint16 value_ses_pres = 0;

		root_tree = tree;

		/* data pointer */
		/* decode as PDV-list */
		if ( (int)(intptr_t)  data == FALSE )
		{
				ti = proto_tree_add_item(
						tree,
						proto_atn_ulcs,
						tvb,
						0,
						0 ,
						ENC_NA);

				atn_ulcs_tree = proto_item_add_subtree(
						ti,
						ett_atn_ulcs);

				dissect_Fully_encoded_data_PDU(
						tvb,
						pinfo,
						atn_ulcs_tree);

				return offset +
					tvb_reported_length_remaining(tvb, offset ) ;
		}

		/* decode as SPDU, PPDU and ACSE PDU */
		if ( (int)(intptr_t)  data == TRUE )
		{
				/* get session and presentation PDU's */
				value_ses_pres = tvb_get_ntohs(tvb, offset);

				/* SPDU: dissect session layer */
				atn_ulcs_tree = proto_tree_add_subtree(
						tree, tvb, offset, 0,
						ett_atn_ses, NULL, ATN_SES_PROTO );

				/* get SPDU (1 octet) */
				value_ses = tvb_get_guint8(tvb, offset);

				/* SPDU type/identifier  */
				proto_tree_add_item(atn_ulcs_tree,
						hf_atn_ses_type,
						tvb,
						offset,
						1,
						ENC_BIG_ENDIAN );

				/* SPDU parameters may be present in Short Refuse */
				/* or Short Refuse Continue SPDU's */
				switch(value_ses & SES_PDU_TYPE_MASK){
						case SES_ATN_SRF:
						case SES_ATN_SRFC:

								/* SPDU parameter presence */
								proto_tree_add_item(atn_ulcs_tree,
										hf_atn_ses_param_ind,
										tvb,
										offset,
										1,
										ENC_BIG_ENDIAN );

								/* parameter B2 */
								proto_tree_add_item(atn_ulcs_tree,
										hf_atn_ses_param_b2,
										tvb,
										offset,
										1,
										ENC_BIG_ENDIAN );

								/* parameter B1 */
								proto_tree_add_item(atn_ulcs_tree,
										hf_atn_ses_param_b1,
										tvb,
										offset,
										1,
										ENC_BIG_ENDIAN );

							break;
						default:
							break;
				}
				offset++;

				/* PPDU: dissect presentation layer */
				atn_ulcs_tree = proto_tree_add_subtree(
						tree, tvb, offset, 0,
						ett_atn_pres, NULL, ATN_PRES_PROTO );

				value_pres = tvb_get_guint8(tvb, offset);

				/* need session context to identify PPDU type */
				/* note: */
				/* it is *unfeasible* to use proto_tree_add_item here: */
				/* presentation type is always the same constant but its type */
				/* is implicitly determined by preceding session context */
				proto_tree_add_text(atn_ulcs_tree,
						tvb,
						offset,
						1,
						"%s (0x%02x)",
						val_to_str( value_ses_pres & ATN_SES_PRES_MASK , atn_pres_vals, "?"),
						value_pres);

				/* PPDU errorcode in case of SRF/CPR */
				switch(value_ses & SES_PDU_TYPE_MASK){
						case SES_ATN_SRF:
						case SES_ATN_SRFC:
								proto_tree_add_item(
										atn_ulcs_tree,
										hf_atn_pres_err,
										tvb,
										offset,
										1,
										ENC_BIG_ENDIAN );
								break;
						default:
								break;
				}

				offset++;

				/* ACSE PDU: dissect application layer */
				atn_ulcs_tree = proto_tree_add_subtree(
						tree, tvb, offset, 0,
						ett_atn_acse, NULL, ATN_ACSE_PROTO );

				dissect_ACSE_apdu_PDU(
						tvb_new_subset_remaining(tvb, offset),
						pinfo,
						atn_ulcs_tree);

				return offset +
						tvb_reported_length_remaining(tvb, offset );
		}
		return offset;
}

static gboolean dissect_atn_ulcs_heur(
		tvbuff_t *tvb,
		packet_info *pinfo,
		proto_tree *tree,
		void *data _U_)
{
		/* do we have enough data*/
		/* at least session + presentation data or pdv-list */
		if (tvb_captured_length(tvb) < 2){
				return FALSE; }

		/* check for session/presentation/ACSE PDU's  */
		/* SPDU and PPDU are one octet each */
		switch( tvb_get_ntohs(tvb, 0) & 0xf8ff ){
				case 0xe802: /* SCN + CP*/
				case 0xf802: /* SCNC + CP */
				case 0xf002: /* SAC + CPA */
				case 0xd802: /* SACC + CPA */
				case 0xe002: /* SRF + CPR + R0 */
				case 0xe012: /* SRF + CPR + R1 */
				case 0xe022: /* SRF + CPR + R2 */
				case 0xe032: /* SRF + CPR + R3 */
				case 0xe042: /* SRF + CPR + R4 */
				case 0xe052: /* SRF + CPR + R5 */
				case 0xe062: /* SRF + CPR + R6 */
				case 0xe072: /* SRF + CPR + R7 */
				case 0xa002: /* SRFC + CPR + R0*/
				case 0xa012: /* SRFC + CPR + R1*/
				case 0xa022: /* SRFC + CPR + R2*/
				case 0xa032: /* SRFC + CPR + R3*/
				case 0xa042: /* SRFC + CPR + R4*/
				case 0xa052: /* SRFC + CPR + R5*/
				case 0xa062: /* SRFC + CPR + R6*/
				case 0xa072: /* SRFC + CPR + R7*/
						/* indicate to dissector routine */
						/* that a least SPDU, PPDU and */
						/* ACSE PDU is present */
						dissect_atn_ulcs(
								tvb,
								pinfo,
								tree,
								(void*) TRUE);
						return TRUE;
				default:	/* no SPDU */
						break;
		}

		/* try to detect "Fully-encoded-data" heuristically */
		/* the constants listed match the ASN.1 PER encoding */
		/* of PDV-List */
		switch(  tvb_get_ntohs(tvb, 0) & 0xfff0 ){
				case 0x0020: /* acse-apdu */
				case 0x00a0: /* user-ase-apdu */
				/* indicate to dissector routine */
				/* that a PDV-list PDU is present */
				/*  */
				/* PDV-list PDU may contain */
				/* application protocol data (CM, CPDLC) */
				/* or an ACSE PDU */
						dissect_atn_ulcs(tvb, pinfo, tree, (void*) FALSE);
						return TRUE;
						break;
				default:	/* no or unsupported PDU */
						break;
		}
		return FALSE;
}

void proto_register_atn_ulcs (void)
{
		static hf_register_info hf_atn_ulcs[] = {
				#include "packet-atn-ulcs-hfarr.c"
				{&hf_atn_ses_type,
				{ "SPDU Type",
					"atn-ulcs.ses.type",
					FT_UINT8,
					BASE_HEX,
					VALS(atn_ses_type),
					0xf8,
					"Indicates presence of session parameters",
					HFILL}},
				{&hf_atn_ses_param_ind,
				{ "SPDU Parameter Indication",
					"atn-ulcs.ses.parameter-indication",
					FT_UINT8,
					BASE_HEX,
					VALS(atn_ses_param_ind),
					SES_PARAM_IND_MASK,
					"Indicates presence of session parameters",
					HFILL}},
			{&hf_atn_ses_param_b1,
				{ "SRF Parameter B1",
					"atn-ulcs.ses.srf-b1",
					FT_UINT8,
					BASE_HEX,
					VALS(srf_b1),
					0x01,
					"Determines if transport connection reject is \
					transient or persistent",
					HFILL}},
			{&hf_atn_ses_param_b2,
				{ "SRF Parameter B2",
					"atn-ulcs.ses.srf-b2",
					FT_UINT8,
					BASE_HEX,
					VALS(srf_b2),
					0x02,
					"Determines if transport connection is \
					retained or released",
					HFILL}},
			{ &hf_atn_pres_err,
				{ "Error Code", "atn-ulcs.pres.cpr-error",
					FT_UINT8,
					BASE_HEX,
					VALS(atn_pres_err),
					PRES_CPR_ER_MASK,
					NULL,
					HFILL}},
		};

		static gint *ett[] = {
				#include "packet-atn-ulcs-ettarr.c"
				&ett_atn_ses,
				&ett_atn_pres,
				&ett_atn_acse,
				&ett_atn_ulcs
    };

		proto_atn_ulcs = proto_register_protocol (
				ATN_ULCS_PROTO ,
				"ATN-ULCS",
				"atn-ulcs");

		proto_register_field_array (
				proto_atn_ulcs,
				hf_atn_ulcs,
				array_length(hf_atn_ulcs));

		proto_register_subtree_array (
				ett,
				array_length (ett));

		new_register_dissector(
				"atn-ulcs",
				dissect_atn_ulcs,
				proto_atn_ulcs);

		atn_cm_handle = find_dissector("atn-cm");
		atn_cpdlc_handle = find_dissector("atn-cpdlc");

		/* initiate sub dissector list */
		register_heur_dissector_list(
				"atn-ulcs",
				&atn_ulcs_heur_subdissector_list);

		/* init aare/aare data */
		aarq_data_tree = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());

		atn_conversation_tree = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
}

void proto_reg_handoff_atn_ulcs(void)
{
		/* add session dissector to cotp dissector list dissector list*/
		heur_dissector_add(
				"cotp",
				dissect_atn_ulcs_heur,
				proto_atn_ulcs);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 2
 * tab-width: 2
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=2 tabstop=2 noexpandtab:
 * :indentSize=2:tabSize=2:noTabs=false:
 */
