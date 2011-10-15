/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* packet-h225.h                                                              */
/* ../../tools/asn2wrs.py -p h225 -c ./h225.cnf -s ./packet-h225-template -D . -O ../../epan/dissectors H323-MESSAGES.asn */

/* Input file: packet-h225-template.h */

#line 1 "../../asn1/h225/packet-h225-template.h"
/* packet-h225.h
 * Routines for h225 packet dissection
 * Copyright 2005, Anders Broman <anders.broman@ericsson.com>
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
 */

#ifndef PACKET_H225_H
#define PACKET_H225_H

typedef enum _h225_msg_type {
	H225_RAS,
	H225_CS,
	H225_OTHERS
} h225_msg_type;

typedef enum _h225_cs_type {
    H225_SETUP,
    H225_CALL_PROCEDING,
    H225_CONNECT,
    H225_ALERTING,
    H225_INFORMATION,
    H225_RELEASE_COMPLET,
    H225_FACILITY,
    H225_PROGRESS,
    H225_EMPTY,
    H225_STATUS,
    H225_STATUS_INQUIRY,
    H225_SETUP_ACK,
    H225_NOTIFY,
    H225_OTHER
} h225_cs_type;

typedef struct _h225_packet_info {
	h225_msg_type msg_type;		/* ras or cs message */
	h225_cs_type cs_type;		/* cs message type */
	gint msg_tag;			/* message tag*/
	gint reason;			/* reason tag, if available */
	guint requestSeqNum;		/* request sequence number of ras-message, if available */
	e_guid_t guid;			/* globally unique call id */
	gboolean is_duplicate;		/* true, if this is a repeated message */
	gboolean request_available;	/* true, if response matches to a request */
	nstime_t delta_time; 		/* this is the RAS response time delay */
	/* added for h225 conversations analysis */
	gboolean is_faststart;		/* true, if faststart field is included */
	gboolean is_h245;
	gboolean is_h245Tunneling;
	guint32 h245_address;
	guint16 h245_port;
	gchar dialedDigits[129]; /* Dialed Digits in the LRQ and LCF used for voip analysis */
	gboolean is_destinationInfo;
	gchar frame_label[50]; /* the Fram label used by graph_analysis, what is a abreviation of cinfo */
} h225_packet_info;

/*
 * the following allows TAP code access to the messages
 * without having to duplicate it. With MSVC and a 
 * libwireshark.dll, we need a special declaration.
 */

#include <epan/asn1.h>
#include <epan/dissectors/packet-per.h>


/*--- Included file: packet-h225-exp.h ---*/
#line 1 "../../asn1/h225/packet-h225-exp.h"
WS_VAR_IMPORT const value_string T_h323_message_body_vals[];
WS_VAR_IMPORT const value_string h225_ReleaseCompleteReason_vals[];
extern const value_string h225_PresentationIndicator_vals[];
extern const value_string h225_ScreeningIndicator_vals[];
WS_VAR_IMPORT const value_string FacilityReason_vals[];
extern const value_string h225_TransportAddress_vals[];
extern const value_string h225_SupportedProtocols_vals[];
extern const value_string AliasAddress_vals[];
extern const value_string h225_PartyNumber_vals[];
extern const value_string h225_PublicTypeOfNumber_vals[];
extern const value_string h225_PrivateTypeOfNumber_vals[];
extern const value_string h225_IntegrityMechanism_vals[];
extern const value_string h225_CryptoH323Token_vals[];
extern const value_string h225_GenericIdentifier_vals[];
WS_VAR_IMPORT const value_string h225_RasMessage_vals[];
WS_VAR_IMPORT const value_string GatekeeperRejectReason_vals[];
WS_VAR_IMPORT const value_string RegistrationRejectReason_vals[];
WS_VAR_IMPORT const value_string UnregRequestReason_vals[];
WS_VAR_IMPORT const value_string UnregRejectReason_vals[];
extern const value_string h225_TransportQOS_vals[];
WS_VAR_IMPORT const value_string AdmissionRejectReason_vals[];
WS_VAR_IMPORT const value_string BandRejectReason_vals[];
WS_VAR_IMPORT const value_string LocationRejectReason_vals[];
WS_VAR_IMPORT const value_string DisengageReason_vals[];
WS_VAR_IMPORT const value_string DisengageRejectReason_vals[];
WS_VAR_IMPORT const value_string InfoRequestNakReason_vals[];
int dissect_h225_ReleaseCompleteReason(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_h225_PresentationIndicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_h225_ScreeningIndicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_h225_TransportAddress(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_h225_EndpointType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_h225_SupportedProtocols(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_h225_TunnelledProtocol(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_h225_NonStandardParameter(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_h225_AliasAddress(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_h225_PartyNumber(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_h225_PublicTypeOfNumber(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_h225_PrivateTypeOfNumber(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_h225_AlternateTransportAddresses(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_h225_GloballyUniqueID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_h225_ConferenceIdentifier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_h225_GatekeeperIdentifier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_h225_BandWidth(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_h225_CallReferenceValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_h225_TimeToLive(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_h225_CallIdentifier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_h225_IntegrityMechanism(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_h225_ICV(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_h225_CryptoH323Token(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_h225_CircuitInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_h225_CircuitIdentifier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_h225_ServiceControlSession(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_h225_GenericData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_h225_GenericIdentifier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_h225_FeatureSet(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_h225_TransportChannelInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_h225_RasMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_h225_TransportQOS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_h225_ExtendedAliasAddress_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_);

/*--- End of included file: packet-h225-exp.h ---*/
#line 83 "../../asn1/h225/packet-h225-template.h"

#endif  /* PACKET_H225_H */


