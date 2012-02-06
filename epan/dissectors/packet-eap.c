/* packet-eap.c
 * Routines for EAP Extensible Authentication Protocol dissection
 * RFC 2284, RFC 3748
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/ppptypes.h>
#include <epan/reassemble.h>
#include <epan/emem.h>
#include <epan/eap.h>

#include "packet-wps.h"

static int proto_eap = -1;
static int hf_eap_code = -1;
static int hf_eap_identifier = -1;
static int hf_eap_len = -1;
static int hf_eap_type = -1;
static int hf_eap_type_nak = -1;

static gint ett_eap = -1;

static dissector_handle_t ssl_handle;



const value_string eap_code_vals[] = {
    { EAP_REQUEST,  "Request" },
    { EAP_RESPONSE, "Response" },
    { EAP_SUCCESS,  "Success" },
    { EAP_FAILURE,  "Failure" },
    { EAP_INITIATE, "Initiate" }, /* [RFC5296] */
    { EAP_FINISH,   "Finish" },   /* [RFC5296] */
    { 0,            NULL }
};

/*
References:
  1) http://www.iana.org/assignments/ppp-numbers
			PPP EAP REQUEST/RESPONSE TYPES
  2) http://www.ietf.org/internet-drafts/draft-ietf-pppext-rfc2284bis-02.txt
  3) RFC2284
  4) RFC3748
  5) http://www.iana.org/assignments/eap-numbers	EAP registry (updated 2009-02-25)
*/

const value_string eap_type_vals[] = {
  {  1,          "Identity [RFC3748]" },
  {  2,          "Notification [RFC3748]" },
  {  3,          "Legacy Nak (Response only) [RFC3748]" },
  {  4,          "MD5-Challenge [RFC3748]" },
  {  5,          "One Time Password (OTP) [RFC3748]" },
  {  6,          "Generic Token Card [RFC3748]" },
  {  7,          "Allocated" },
  {  8,          "Allocated" },
  {  9,          "RSA Public Key Authentication [Whelan]" },
  { 10,          "DSS Unilateral [Nace]" },
  { 11,          "KEA [Nace]" },
  { 12,          "KEA-VALIDATE [Nace]" },
  { 13,          "EAP-TLS [RFC5216] [Aboba]" },
  { 14,          "Defender Token (AXENT) [Rosselli]" },
  { 15,          "RSA Security SecurID EAP [Nystrom]" },
  { 16,          "Arcot Systems EAP [Jerdonek]" },
  { 17,          "EAP-Cisco Wireless (LEAP) [Norman]" },
  { 18,          "GSM Subscriber Identity Modules (EAP-SIM) [RFC4186]" },
  { 19,          "SRP-SHA1 Part 1 [Carlson]" },
  { 20,          "Unassigned" },
  { 21,          "EAP-TTLS [RFC5281]" },
  { 22,          "Remote Access Service [Fields]" },
  { 23,          "EAP-AKA Authentication [RFC4187]" },
  { 24,          "EAP-3Com Wireless [Young]" },
  { 25,          "PEAP [Palekar]" },
  { 26,          "MS-EAP-Authentication [Palekar]" },
  { 27,          "Mutual Authentication w/Key Exchange (MAKE)[Berrendonner]" },
  { 28,          "CRYPTOCard [Webb]" },
  { 29,          "EAP-MSCHAP-V2 [Potter]" },
  { 30,          "DynamID [Merlin]" },
  { 31,          "Rob EAP [Ullah]" },
  { 32,          "Protected One-Time Password [RFC4793] [Nystrom]" },
  { 33,          "MS-Authentication-TLV [Palekar]" },
  { 34,          "SentriNET [Kelleher]" },
  { 35,          "EAP-Actiontec Wireless [Chang]" },
  { 36,          "Cogent Systems Biometrics Authentication EAP [Xiong]" },
  { 37,          "AirFortress EAP [Hibbard]" },
  { 38,          "EAP-HTTP Digest [Tavakoli]" },
  { 39,          "SecureSuite EAP [Clements]" },
  { 40,          "DeviceConnect EAP [Pitard]" },
  { 41,          "EAP-SPEKE [Zick]" },
  { 42,          "EAP-MOBAC [Rixom]" },
  { 43,          "EAP-FAST [RFC4851]" },
  { 44,          "ZoneLabs EAP (ZLXEAP) [Bogue]" },
  { 45,          "EAP-Link [Zick]" },
  { 46,          "EAP-PAX [Clancy]" },
  { 47,          "EAP-PSK [RFC4764]" },
  { 48,          "EAP-SAKE [RFC4763]" },
  { 49,          "EAP-IKEv2 [RFC5106]" },
  { 50,          "EAP-AKA' [RFC5448]" },
  { 51,          "EAP-GPSK [RFC5433]" },
  { 53,          "EAP-pwd [RFC-harkins-emu-eap-pwd-12.txt]" },
  { 254,         "Expanded Type [RFC3748]" },
  { 255,         "Experimental [RFC3748]" },
  { 0,          NULL }

};

/*
 * State information for EAP-TLS (RFC2716) and Lightweight EAP:
 *
 *	http://www.missl.cs.umd.edu/wireless/ethereal/leap.txt
 *
 * Attach to all conversations:
 *
 *	a sequence number to be handed to "fragment_add_seq()" as
 *	the fragment sequence number - if it's -1, no reassembly
 *	is in progress, but if it's not, it's the sequence number
 *	to use for the current fragment;
 *
 *	a value to be handed to "fragment_add_seq()" as the
 *	reassembly ID - when a reassembly is started, it's set to
 *	the frame number of the current frame, i.e. the frame
 *	that starts the reassembly;
 *
 *	an indication of the current state of LEAP negotiation,
 *	with -1 meaning no LEAP negotiation is in progress.
 *
 * Attach to frames containing fragments of EAP-TLS messages the
 * reassembly ID for those fragments, so we can find the reassembled
 * data after the first pass through the packets.
 *
 * Attach to LEAP frames the state of the LEAP negotiation when the
 * frame was processed, so we can properly dissect
 * the LEAP message after the first pass through the packets.
 *
 * Attach to all conversations both pieces of information, to keep
 * track of EAP-TLS reassembly and the LEAP state machine.
 */

typedef struct {
	int	eap_tls_seq;
	guint32	eap_reass_cookie;
	int	leap_state;
} conv_state_t;

typedef struct {
	int	info;	/* interpretation depends on EAP message type */
} frame_state_t;

/*********************************************************************
                           EAP-TLS
RFC2716
**********************************************************************/

/*
from RFC2716, pg 17

   Flags

      0 1 2 3 4 5 6 7 8
      +-+-+-+-+-+-+-+-+
      |L M S R R Vers |
      +-+-+-+-+-+-+-+-+

      L = Length included
      M = More fragments
      S = EAP-TLS start
      R = Reserved
      Vers = PEAP version (Reserved for TLS and TTLS)
*/

#define EAP_TLS_FLAG_L 0x80 /* Length included */
#define EAP_TLS_FLAG_M 0x40 /* More fragments  */
#define EAP_TLS_FLAG_S 0x20 /* EAP-TLS start   */
#define EAP_PEAP_FLAG_VERSION 0x07 /* EAP-PEAP version */

/*
 * reassembly of EAP-TLS
 */
static GHashTable *eaptls_fragment_table = NULL;

static int   hf_eaptls_fragment  = -1;
static int   hf_eaptls_fragments = -1;
static int   hf_eaptls_fragment_overlap = -1;
static int   hf_eaptls_fragment_overlap_conflict = -1;
static int   hf_eaptls_fragment_multiple_tails = -1;
static int   hf_eaptls_fragment_too_long_fragment = -1;
static int   hf_eaptls_fragment_error = -1;
static int   hf_eaptls_fragment_count = -1;
static int   hf_eaptls_reassembled_length = -1;
static gint ett_eaptls_fragment  = -1;
static gint ett_eaptls_fragments = -1;
static gint ett_eap_sim_attr = -1;
static gint ett_eap_aka_attr = -1;
static gint ett_eap_exp_attr = -1;

static const fragment_items eaptls_frag_items = {
	&ett_eaptls_fragment,
	&ett_eaptls_fragments,
	&hf_eaptls_fragments,
	&hf_eaptls_fragment,
	&hf_eaptls_fragment_overlap,
	&hf_eaptls_fragment_overlap_conflict,
	&hf_eaptls_fragment_multiple_tails,
	&hf_eaptls_fragment_too_long_fragment,
	&hf_eaptls_fragment_error,
	&hf_eaptls_fragment_count,
	NULL,
	&hf_eaptls_reassembled_length,
	"fragments"
};

/**********************************************************************
 Support for EAP Expanded Type.

 Currently this is limited to WifiProtectedSetup. Maybe we need
 a generic method to support EAP extended types ?
*********************************************************************/
static int   hf_eapext_vendorid   = -1;
static int   hf_eapext_vendortype = -1;

/* Vendor-Type and Vendor-id */
#define WFA_VENDOR_ID         0x00372A
#define WFA_SIMPLECONFIG_TYPE 0x1

static const value_string eapext_vendorid_vals[] = {
  { WFA_VENDOR_ID, "WFA" },
  { 0, NULL }
};

static const value_string eapext_vendortype_vals[] = {
  { WFA_SIMPLECONFIG_TYPE, "SimpleConfig" },
  { 0, NULL }
};

static void
dissect_exteap(proto_tree *eap_tree, tvbuff_t *tvb, int offset,
	       gint size, packet_info* pinfo)
{

  proto_tree_add_item(eap_tree, hf_eapext_vendorid,   tvb, offset, 3, ENC_BIG_ENDIAN);
  offset += 3; size -= 3;

  proto_tree_add_item(eap_tree, hf_eapext_vendortype, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4; size -= 4;

  /* Generic method to support multiple vendor-defined extended types goes here :-) */
  dissect_exteap_wps(eap_tree, tvb, offset, size, pinfo);
}
/* *********************************************************************
********************************************************************* */

static gboolean
test_flag(unsigned char flag, unsigned char mask)
{
  return ( ( flag & mask ) != 0 );
}

static void
eaptls_defragment_init(void)
{
  fragment_table_init(&eaptls_fragment_table);
}

static void
dissect_eap_mschapv2(proto_tree *eap_tree, tvbuff_t *tvb, int offset,
		     gint size)
{
	gint left = size;
	gint ms_len;
	guint8 value_size;
	enum {
		MS_CHAPv2_CHALLENGE = 1,
		MS_CHAPv2_RESPONSE = 2,
		MS_CHAPv2_SUCCESS = 3,
		MS_CHAPv2_FAILURE = 4,
		MS_CHAPv2_CHANGE_PASSWORD = 5
	} opcode;
	static const value_string opcodes[] = {
		{ MS_CHAPv2_CHALLENGE, "Challenge" },
		{ MS_CHAPv2_RESPONSE, "Response" },
		{ MS_CHAPv2_SUCCESS, "Success" },
		{ MS_CHAPv2_FAILURE, "Failure" },
		{ MS_CHAPv2_CHANGE_PASSWORD, "Change-Password" },
		{ 0, NULL }
	};

	/* OpCode (1 byte), MS-CHAPv2-ID (1 byte), MS-Length (2 bytes), Data */
	opcode = tvb_get_guint8(tvb, offset);
	proto_tree_add_text(eap_tree, tvb, offset, 1,
			    "OpCode: %d (%s)",
			    opcode, val_to_str(opcode, opcodes, "Unknown"));
	offset++;
	left--;
	if (left <= 0)
		return;

	proto_tree_add_text(eap_tree, tvb, offset, 1, "MS-CHAPv2-ID: %d",
			    tvb_get_guint8(tvb, offset));
	offset++;
	left--;
	if (left <= 0)
		return;

	ms_len = tvb_get_ntohs(tvb, offset);
	proto_tree_add_text(eap_tree, tvb, offset, 2, "MS-Length: %d%s",
			    ms_len,
			    ms_len != size ? " (invalid len)" : "");
	offset += 2;
	left -= 2;

	switch (opcode) {
	case MS_CHAPv2_CHALLENGE:
		if (left <= 0)
			break;
		value_size = tvb_get_guint8(tvb, offset);
		proto_tree_add_text(eap_tree, tvb, offset, 1,
				    "Value-Size: %d", value_size);
		offset++;
		left--;
		proto_tree_add_text(eap_tree, tvb, offset, value_size,
				    "Challenge: %s",
				    tvb_bytes_to_str(tvb, offset, value_size));
		offset += value_size;
		left -= value_size;
		if (left <= 0)
			break;
		proto_tree_add_text(eap_tree, tvb, offset, left,
				    "Name: %s",
				    tvb_format_text(tvb, offset, left));
		break;
	case MS_CHAPv2_RESPONSE:
		if (left <= 0)
			break;
		value_size = tvb_get_guint8(tvb, offset);
		proto_tree_add_text(eap_tree, tvb, offset, 1,
				    "Value-Size: %d", value_size);
		offset++;
		left--;
		if (value_size == 49) {
			proto_tree_add_text(eap_tree, tvb, offset, 16,
					    "Peer-Challenge: %s",
					    tvb_bytes_to_str(tvb, offset, 16));
			offset += 16;
			proto_tree_add_text(eap_tree, tvb, offset, 8,
					    "Reserved, must be zero: %s",
					    tvb_bytes_to_str(tvb, offset, 8));
			offset += 8;
			proto_tree_add_text(eap_tree, tvb, offset, 24,
					    "NT-Response: %s",
					    tvb_bytes_to_str(tvb, offset, 24));
			offset += 24;
			proto_tree_add_text(eap_tree, tvb, offset, 1,
					    "Flags: %d",
					    tvb_get_guint8(tvb, offset));
			offset++;
			left -= value_size;
		} else {
			proto_tree_add_text(eap_tree, tvb, offset, value_size,
					    "Response (unknown length): %s",
					    tvb_bytes_to_str(tvb, offset,
							     value_size));
			offset += value_size;
			left -= value_size;
		}
		if (left <= 0)
			break;
		proto_tree_add_text(eap_tree, tvb, offset, left,
				    "Name: %s",
				    tvb_format_text(tvb, offset, left));
		break;
	case MS_CHAPv2_SUCCESS:
		if (left <= 0)
			break;
		proto_tree_add_text(eap_tree, tvb, offset, left,
				    "Message: %s",
				    tvb_format_text(tvb, offset, left));
		break;
	case MS_CHAPv2_FAILURE:
		if (left <= 0)
			break;
		proto_tree_add_text(eap_tree, tvb, offset, left,
				    "Failure Request: %s",
				    tvb_format_text(tvb, offset, left));
		break;
	default:
		proto_tree_add_text(eap_tree, tvb, offset, left,
				    "Data (%d byte%s) Value: %s",
				    left, plurality(left, "", "s"),
				    tvb_bytes_to_str(tvb, offset, left));
		break;
	}
}

static void
dissect_eap_sim(proto_tree *eap_tree, tvbuff_t *tvb, int offset, gint size)
{
	gint left = size;
	enum {
		SIM_START = 10,
		SIM_CHALLENGE = 11,
		SIM_NOTIFICATION = 12,
		SIM_RE_AUTHENTICATION = 13,
		SIM_CLIENT_ERROR = 14
	} subtype;
	static const value_string subtypes[] = {
		{ SIM_START, "Start" },
		{ SIM_CHALLENGE, "Challenge" },
		{ SIM_NOTIFICATION, "Notification" },
		{ SIM_RE_AUTHENTICATION, "Re-authentication" },
		{ SIM_CLIENT_ERROR, "Client-Error" },
		{ 0, NULL }
	};
	static const value_string attributes[] = {
		{ 1, "AT_RAND" },
		{ 6, "AT_PADDING" },
		{ 7, "AT_NONCE_MT" },
		{ 10, "AT_PERMANENT_ID_REQ" },
		{ 11, "AT_MAC" },
		{ 12, "AT_NOTIFICATION" },
		{ 13, "AT_ANY_ID_REQ" },
		{ 14, "AT_IDENTITY" },
		{ 15, "AT_VERSION_LIST" },
		{ 16, "AT_SELECTED_VERSION" },
		{ 17, "AT_FULLAUTH_ID_REQ" },
		{ 19, "AT_COUNTER" },
		{ 20, "AT_COUNTER_TOO_SMALL" },
		{ 21, "AT_NONCE_S" },
		{ 22, "AT_CLIENT_ERROR_CODE" },
		{ 129, "AT_IV" },
		{ 130, "AT_ENCR_DATA" },
		{ 132, "AT_NEXT_PSEUDONYM" },
		{ 133, "AT_NEXT_REAUTH_ID" },
		{ 135, "AT_RESULT_IND" },
		{ 0, NULL }
	};

	subtype = tvb_get_guint8(tvb, offset);
	proto_tree_add_text(eap_tree, tvb, offset, 1,
			    "subtype: %d (%s)",
			    subtype, val_to_str(subtype, subtypes, "Unknown"));

	offset++;
	left--;

	if (left < 2)
		return;
	proto_tree_add_text(eap_tree, tvb, offset, 2, "Reserved: %d",
			    tvb_get_ntohs(tvb, offset));
	offset += 2;
	left -= 2;

	/* Rest of EAP-SIM data is in Type-Len-Value format. */
	while (left >= 2) {
		guint8 type, length;
		proto_item *pi;
		proto_tree *attr_tree;
		int aoffset;
		gint aleft;
		aoffset = offset;
		type = tvb_get_guint8(tvb, aoffset);
		length = tvb_get_guint8(tvb, aoffset + 1);
		aleft = 4 * length;

		pi = proto_tree_add_text(eap_tree, tvb, aoffset, aleft,
					 "Attribute: %s",
					 val_to_str(type, attributes,
						    "Unknown %u"));
		attr_tree = proto_item_add_subtree(pi, ett_eap_sim_attr);
		proto_tree_add_text(attr_tree, tvb, aoffset, 1,
				    "Type: %u", type);
		aoffset++;
		aleft--;

		if (aleft <= 0)
			break;
		proto_tree_add_text(attr_tree, tvb, aoffset, 1,
				    "Length: %d (%d bytes)",
				    length, 4 * length);
		aoffset++;
		aleft--;
		proto_tree_add_text(attr_tree, tvb, aoffset, aleft,
				    "Value: %s",
				    tvb_bytes_to_str(tvb, aoffset, aleft));

		offset += 4 * length;
		left -= 4 * length;
	}
}

static void
dissect_eap_aka(proto_tree *eap_tree, tvbuff_t *tvb, int offset, gint size)
{
	gint left = size;
	enum {
		AKA_CHALLENGE = 1,
		AKA_AUTHENTICATION_REJECT = 2,
		AKA_SYNCHRONIZATION_FAILURE = 4,
		AKA_IDENTITY = 5,
		AKA_NOTIFICATION = 12,
		AKA_REAUTHENTICATION = 13,
		AKA_CLIENT_ERROR = 14
	} subtype;
	static const value_string subtypes[] = {
		{ AKA_CHALLENGE, "AKA-Challenge" },
		{ AKA_AUTHENTICATION_REJECT, "AKA-Authentication-Reject" },
		{ AKA_SYNCHRONIZATION_FAILURE, "AKA-Synchronization-Failure" },
		{ AKA_IDENTITY, "AKA-Identity" },
		{ AKA_NOTIFICATION, "Notification" },
		{ AKA_REAUTHENTICATION, "Re-authentication" },
		{ AKA_CLIENT_ERROR, "Client-Error" },
		{ 0, NULL }
	};
	static const value_string attributes[] = {
		{ 1, "AT_RAND" },
		{ 2, "AT_AUTN" },
		{ 3, "AT_RES" },
		{ 4, "AT_AUTS" },
		{ 6, "AT_PADDING" },
		{ 10, "AT_PERMANENT_ID_REQ" },
		{ 11, "AT_MAC" },
		{ 12, "AT_NOTIFICATION" },
		{ 13, "AT_ANY_ID_REQ" },
		{ 14, "AT_IDENTITY" },
		{ 17, "AT_FULLAUTH_ID_REQ" },
		{ 19, "AT_COUNTER" },
		{ 20, "AT_COUNTER_TOO_SMALL" },
		{ 21, "AT_NONCE_S" },
		{ 22, "AT_CLIENT_ERROR_CODE" },
		{ 23,  "AT_KDF_INPUT"},
		{ 24,  "AT_KDF"},
		{ 129, "AT_IV" },
		{ 130, "AT_ENCR_DATA" },
		{ 132, "AT_NEXT_PSEUDONYM" },
		{ 133, "AT_NEXT_REAUTH_ID" },
		{ 134, "AT_CHECKCODE" },
		{ 135, "AT_RESULT_IND" },
		{ 0, NULL }
	};

	subtype = tvb_get_guint8(tvb, offset);
	proto_tree_add_text(eap_tree, tvb, offset, 1,
			    "subtype: %d (%s)",
			    subtype, val_to_str(subtype, subtypes, "Unknown"));

	offset++;
	left--;

	if (left < 2)
		return;
	proto_tree_add_text(eap_tree, tvb, offset, 2, "Reserved: %d",
			    tvb_get_ntohs(tvb, offset));
	offset += 2;
	left -= 2;

	/* Rest of EAP-AKA data is in Type-Len-Value format. */
	while (left >= 2) {
		guint8 type, length;
		proto_item *pi;
		proto_tree *attr_tree;
		int aoffset;
		gint aleft;
		aoffset = offset;
		type = tvb_get_guint8(tvb, aoffset);
		length = tvb_get_guint8(tvb, aoffset + 1);
		aleft = 4 * length;

		pi = proto_tree_add_text(eap_tree, tvb, aoffset, aleft,
					 "Attribute: %s",
					 val_to_str(type, attributes,
						    "Unknown %u"));
		attr_tree = proto_item_add_subtree(pi, ett_eap_aka_attr);
		proto_tree_add_text(attr_tree, tvb, aoffset, 1,
				    "Type: %u", type);
		aoffset++;
		aleft--;

		if (aleft <= 0)
			break;
		proto_tree_add_text(attr_tree, tvb, aoffset, 1,
				    "Length: %d (%d bytes)",
				    length, 4 * length);
		aoffset++;
		aleft--;
		proto_tree_add_text(attr_tree, tvb, aoffset, aleft,
				    "Value: %s",
				    tvb_bytes_to_str(tvb, aoffset, aleft));

		offset += 4 * length;
		left -= 4 * length;
	}
}

static int
dissect_eap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  guint8      eap_code;
  guint16     eap_len;
  guint8      eap_type;
  gint        len;
  conversation_t *conversation;
  conv_state_t *conversation_state;
  frame_state_t *packet_state;
  int leap_state;
  proto_tree *ti;
  proto_tree *eap_tree = NULL;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "EAP");
  col_clear(pinfo->cinfo, COL_INFO);

  eap_code = tvb_get_guint8(tvb, 0);

  if (check_col(pinfo->cinfo, COL_INFO))
    col_add_str(pinfo->cinfo, COL_INFO,
		val_to_str(eap_code, eap_code_vals, "Unknown code (0x%02X)"));

  /*
   * Find a conversation to which we belong; create one if we don't find
   * it.
   *
   * We use the source and destination addresses, and the *matched* port
   * number, because if this is running over RADIUS, there's no guarantee
   * that the source port number for request and the destination port
   * number for replies will be the same in all messages - the client
   * may use different port numbers for each request.
   *
   * We have to pair up the matched port number with the corresponding
   * address; we determine which that is by comparing it with the
   * destination port - if it matches, we matched on the destination
   * port (this is a request), otherwise we matched on the source port
   * (this is a reply).
   *
   * XXX - what if we're running over a TCP or UDP protocol with a
   * heuristic dissector, meaning the matched port number won't be set?
   *
   * XXX - what if we have a capture file with captures on multiple
   * PPP interfaces, with LEAP traffic on all of them?  How can we
   * keep them separate?  (Or is that not going to happen?)
   */
  if (pinfo->destport == pinfo->match_uint) {
    conversation = find_conversation(pinfo->fd->num, &pinfo->dst, &pinfo->src,
				     pinfo->ptype, pinfo->destport,
				     0, NO_PORT_B);
  } else {
    conversation = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst,
				     pinfo->ptype, pinfo->srcport,
				     0, NO_PORT_B);
  }
  if (conversation == NULL) {
    if (pinfo->destport == pinfo->match_uint) {
      conversation = conversation_new(pinfo->fd->num, &pinfo->dst, &pinfo->src,
				      pinfo->ptype, pinfo->destport,
				      0, NO_PORT2);
    } else {
      conversation = conversation_new(pinfo->fd->num, &pinfo->src, &pinfo->dst,
				      pinfo->ptype, pinfo->srcport,
				      0, NO_PORT2);
    }
  }

  /*
   * Get the state information for the conversation; attach some if
   * we don't find it.
   */
  conversation_state = conversation_get_proto_data(conversation, proto_eap);
  if (conversation_state == NULL) {
    /*
     * Attach state information to the conversation.
     */
    conversation_state = se_alloc(sizeof (conv_state_t));
    conversation_state->eap_tls_seq = -1;
    conversation_state->eap_reass_cookie = 0;
    conversation_state->leap_state = -1;
    conversation_add_proto_data(conversation, proto_eap, conversation_state);
  }

  /*
   * Set this now, so that it gets remembered even if we throw an exception
   * later.
   */
  if (eap_code == EAP_FAILURE)
    conversation_state->leap_state = -1;

  eap_len = tvb_get_ntohs(tvb, 2);
  len = eap_len;

  if (tree) {
    ti = proto_tree_add_item(tree, proto_eap, tvb, 0, len, ENC_NA);
    eap_tree = proto_item_add_subtree(ti, ett_eap);

    proto_tree_add_uint(eap_tree, hf_eap_code, tvb, 0, 1, eap_code);
  }

  if (tree)
    proto_tree_add_item(eap_tree, hf_eap_identifier, tvb, 1, 1, ENC_BIG_ENDIAN);

  if (tree)
    proto_tree_add_uint(eap_tree, hf_eap_len, tvb, 2, 2, eap_len);

  switch (eap_code) {

  case EAP_SUCCESS:
  case EAP_FAILURE:
    break;

  case EAP_REQUEST:
  case EAP_RESPONSE:
    eap_type = tvb_get_guint8(tvb, 4);

    if (check_col(pinfo->cinfo, COL_INFO))
      col_append_fstr(pinfo->cinfo, COL_INFO, ", %s",
		      val_to_str(eap_type, eap_type_vals,
				 "Unknown type (0x%02x)"));
    if (tree)
      proto_tree_add_uint(eap_tree, hf_eap_type, tvb, 4, 1, eap_type);

    if (len > 5 || (len == 5 && eap_type == EAP_TYPE_ID)) {
      int     offset = 5;
      gint    size   = len - offset;

      switch (eap_type) {
      /*********************************************************************
      **********************************************************************/
      case EAP_TYPE_ID:
	if (tree) {
	  proto_tree_add_text(eap_tree, tvb, offset, size,
			      "Identity (%d byte%s): %s",
			      size, plurality(size, "", "s"),
			      tvb_format_text(tvb, offset, size));
         }
	if(!pinfo->fd->flags.visited) {
	  conversation_state->leap_state = 0;
	  conversation_state->eap_tls_seq = -1;
	}
	break;

      /*********************************************************************
      **********************************************************************/
      case EAP_TYPE_NOTIFY:
	if (tree) {
	  proto_tree_add_text(eap_tree, tvb, offset, size,
			      "Notification (%d byte%s): %s",
			      size, plurality(size, "", "s"),
			      tvb_format_text(tvb, offset, size));
	}
	break;
      /*********************************************************************
      **********************************************************************/
      case EAP_TYPE_NAK:
	if (tree) {
	  proto_tree_add_item(eap_tree, hf_eap_type_nak, tvb,
			      offset, 1, ENC_BIG_ENDIAN);
	}
	break;
      /*********************************************************************
      **********************************************************************/
      case EAP_TYPE_MD5:
	if (tree) {
	  guint8 value_size = tvb_get_guint8(tvb, offset);
	  gint extra_len = size - 1 - value_size;
	  proto_tree_add_text(eap_tree, tvb, offset, 1, "Value-Size: %d%s",
			      value_size,
			      value_size > size - 1 ? " (overflow)": "");
	  if (value_size > size - 1)
	    value_size = size - 1;
	  offset++;
	  proto_tree_add_text(eap_tree, tvb, offset, value_size,
			      "Value: %s",
			      tvb_bytes_to_str(tvb, offset, value_size));
	  offset += value_size;
	  if (extra_len > 0) {
	    proto_tree_add_text(eap_tree, tvb, offset, extra_len,
				"Extra data (%d byte%s): %s", extra_len,
				plurality(extra_len, "", "s"),
				tvb_bytes_to_str(tvb, offset, extra_len));
	  }
	}
	break;
      /*********************************************************************
                                  EAP-TLS
      **********************************************************************/
      case EAP_TYPE_FAST:
      case EAP_TYPE_PEAP:
      case EAP_TYPE_TTLS:
      case EAP_TYPE_TLS:
	{
	guint8 flags   = tvb_get_guint8(tvb, offset);
	gboolean more_fragments;
	gboolean has_length;
	guint32 length;
	int eap_tls_seq = -1;
	guint32 eap_reass_cookie = 0;
	gboolean needs_reassembly = FALSE;

	more_fragments = test_flag(flags,EAP_TLS_FLAG_M);
	has_length = test_flag(flags,EAP_TLS_FLAG_L);
	if (test_flag(flags,EAP_TLS_FLAG_S)) 
		conversation_state->eap_tls_seq = -1;

	/* Flags field, 1 byte */
	if (tree) {
	  proto_tree_add_text(eap_tree, tvb, offset, 1, "Flags(0x%X): %s%s%s",
			      flags,
			      has_length                      ? "Length ":"",
			      more_fragments                  ? "More "  :"",
			      test_flag(flags,EAP_TLS_FLAG_S) ? "Start " :"");
	  if (eap_type == EAP_TYPE_PEAP || eap_type == EAP_TYPE_TTLS ||
	      eap_type == EAP_TYPE_FAST) {
	    proto_tree_add_text(eap_tree, tvb, offset, 1,
				"%s version %d",
				eap_type == EAP_TYPE_PEAP ? "PEAP" :
				(eap_type == EAP_TYPE_TTLS ? "TTLS" : "FAST"),
				flags & EAP_PEAP_FLAG_VERSION);
	  }
	}
	size--;
	offset++;

	/* Length field, 4 bytes, OPTIONAL. */
	if ( has_length ) {
	  length = tvb_get_ntohl(tvb, offset);
	  if (tree)
	    proto_tree_add_text(eap_tree, tvb, offset, 4, "Length: %i",length);
	  size   -= 4;
	  offset += 4;
	}

	if (size>0) {

	  tvbuff_t *next_tvb;
	  gint tvb_len;
	  gboolean save_fragmented;

	  tvb_len = tvb_length_remaining(tvb, offset);
	  if (size < tvb_len)
	    tvb_len = size;

	    /*
	       EAP/TLS is weird protocol (it comes from
	       Microsoft after all).

	       If we have series of fragmented packets,
	       then there's no way of knowing that from
	       the packet itself, if it is the last packet
	       in series, that is that the packet part of
	       bigger fragmented set of data.

	       The only way to know is, by knowing
	       that we are already in defragmentation
	       "mode" and we are expecing packet
	       carrying fragment of data. (either
	       because we have not received expected
	       amount of data, or because the packet before
	       had "F"ragment flag set.)

	       The situation is alleviated by fact that it
	       is simple ack/nack protcol so there's no
	       place for out-of-order packets like it is
	       possible with IP.

	       Anyway, point of this lengthy essay is that
	       we have to keep state information in the
	       conversation, so that we can put ourselves in
	       defragmenting mode and wait for the last packet,
	       and have to attach state to frames as well, so
	       that we can handle defragmentation after the
	       first pass through the capture.
	    */
	  /* See if we have a remembered defragmentation EAP ID. */
	  packet_state = p_get_proto_data(pinfo->fd, proto_eap);
	  if (packet_state == NULL) {
	    /*
	     * We haven't - does this message require reassembly?
	     */
	    if (!pinfo->fd->flags.visited) {
	      /*
	       * This is the first time we've looked at this frame,
	       * so it wouldn't have any remembered information.
	       *
	       * Therefore, we check whether this conversation has
	       * a reassembly operation in progress, or whether
	       * this frame has the Fragment flag set.
	       */
	      if (conversation_state->eap_tls_seq != -1) {
		/*
		 * There's a reassembly in progress; the sequence number
		 * of the previous fragment is
		 * "conversation_state->eap_tls_seq", and the reassembly
		 * ID is "conversation_state->eap_reass_cookie".
		 *
		 * We must include this frame in the reassembly.
		 * We advance the sequence number, giving us the
		 * sequence number for this fragment.
		 */
		needs_reassembly = TRUE;
		conversation_state->eap_tls_seq++;

		eap_reass_cookie = conversation_state->eap_reass_cookie;
		eap_tls_seq = conversation_state->eap_tls_seq;
	      } else if (more_fragments && has_length) {
		/*
		 * This message has the Fragment flag set, so it requires
		 * reassembly.  It's the message containing the first
		 * fragment (if it's a later fragment, the sequence
		 * number in the conversation state would not be -1).
		 *
		 * If it doesn't include a length, however, we can't
		 * do reassembly (either the message is in error, as
		 * the first fragment *must* contain a length, or we
		 * didn't capture the first fragment, and this just
		 * happens to be the first fragment we saw), so we
		 * also check that we have a length;
		 */
		needs_reassembly = TRUE;
		conversation_state->eap_reass_cookie = pinfo->fd->num;

		/*
		 * Start the reassembly sequence number at 0.
		 */
		conversation_state->eap_tls_seq = 0;

		eap_tls_seq = conversation_state->eap_tls_seq;
		eap_reass_cookie = conversation_state->eap_reass_cookie;
	      }

	      if (needs_reassembly) {
		/*
		 * This frame requires reassembly; remember the reassembly
		 * ID for subsequent accesses to it.
		 */
		packet_state = se_alloc(sizeof (frame_state_t));
		packet_state->info = eap_reass_cookie;
		p_add_proto_data(pinfo->fd, proto_eap, packet_state);
	      }
	    }
	  } else {
	    /*
	     * This frame has a reassembly cookie associated with it, so
	     * it requires reassembly.  We've already done the
	     * reassembly in the first pass, so "fragment_add_seq()"
	     * won't look at the sequence number; set it to 0.
	     *
	     * XXX - a frame isn't supposed to have more than one
	     * EAP message in it, but if it includes both an EAP-TLS
	     * message and a LEAP message, we might be mistakenly
	     * concluding it requires reassembly because the "info"
	     * field isn't -1.  We could, I guess, pack both EAP-TLS
	     * ID and LEAP state into the structure, but that doesn't
	     * work if you have multiple EAP-TLS or LEAP messages in
	     * the frame.
	     *
	     * But it's not clear how much work we should do to handle
	     * a bogus message such as that; as long as we don't crash
	     * or do something else equally horrible, we may not
	     * have to worry about this at all.
	     */
	    needs_reassembly = TRUE;
	    eap_reass_cookie = packet_state->info;
	    eap_tls_seq = 0;
	  }

	  /*
	     We test here to see whether EAP-TLS packet
	     carry fragmented of TLS data.

	     If this is the case, we do reasembly below,
	     otherwise we just call dissector.
	  */
	  if (needs_reassembly) {
	    fragment_data   *fd_head = NULL;

	    /*
	     * Yes, this frame contains a fragment that requires
	     * reassembly.
	     */
	    save_fragmented = pinfo->fragmented;
	    pinfo->fragmented = TRUE;
	    fd_head = fragment_add_seq(tvb, offset, pinfo,
				   eap_reass_cookie,
				   eaptls_fragment_table,
				   eap_tls_seq,
				   size,
				   more_fragments);

	    if (fd_head != NULL)            /* Reassembled  */
	      {
		proto_item *frag_tree_item;

		next_tvb = tvb_new_child_real_data(tvb, fd_head->data,
					     fd_head->len,
					     fd_head->len);
		add_new_data_source(pinfo, next_tvb, "Reassembled EAP-TLS");

		show_fragment_seq_tree(fd_head, &eaptls_frag_items,
		    eap_tree, pinfo, next_tvb, &frag_tree_item);

		call_dissector(ssl_handle, next_tvb, pinfo, eap_tree);

		/*
		 * We're finished reassembing this frame.
		 * Reinitialize the reassembly state.
		 */
		if (!pinfo->fd->flags.visited)
		  conversation_state->eap_tls_seq = -1;
	      }

	    pinfo->fragmented = save_fragmented;

	  } else { /* this data is NOT fragmented */
	    next_tvb = tvb_new_subset(tvb, offset, tvb_len, size);
	    call_dissector(ssl_handle, next_tvb, pinfo, eap_tree);
	  }
	}
	}
	break; /*  EAP_TYPE_TLS */
      /*********************************************************************
                                  Cisco's Lightweight EAP (LEAP)
      http://www.missl.cs.umd.edu/wireless/ethereal/leap.txt
      **********************************************************************/
      case EAP_TYPE_LEAP:
	{
	  guint8  field,count,namesize;

	  /* Version (byte) */
	  if (tree) {
	    field = tvb_get_guint8(tvb, offset);
	    proto_tree_add_text(eap_tree, tvb, offset, 1,
				"Version: %i",field);
	  }
	  offset++;

	  /* Unused  (byte) */
	  if (tree) {
	    field = tvb_get_guint8(tvb, offset);
	    proto_tree_add_text(eap_tree, tvb, offset, 1,
				"Reserved: %i",field);
	  }
	  offset++;

	  /* Count   (byte) */
	  count = tvb_get_guint8(tvb, offset);
	  if (tree) {
	    proto_tree_add_text(eap_tree, tvb, offset, 1,
				"Count: %i",count);
	  }
	  offset++;

	  /* Data    (byte*Count) */
	  /* This part is state-dependent. */

	  /* See if we've already remembered the state. */
	  packet_state = p_get_proto_data(pinfo->fd, proto_eap);
	  if (packet_state == NULL) {
	    /*
	     * We haven't - compute the state based on the current
	     * state in the conversation.
	     */
	    leap_state = conversation_state->leap_state;

	    /* Advance the state machine. */
	    if (leap_state==0) leap_state =  1; else
	    if (leap_state==1) leap_state =  2; else
	    if (leap_state==2) leap_state =  3; else
	    if (leap_state==3) leap_state =  4; else
	    if (leap_state==4) leap_state = -1;

	    /*
	     * Remember the state for subsequent accesses to this
	     * frame.
	     */
	    packet_state = se_alloc(sizeof (frame_state_t));
	    packet_state->info = leap_state;
	    p_add_proto_data(pinfo->fd, proto_eap, packet_state);

	    /*
	     * Update the conversation's state.
	     */
	    conversation_state->leap_state = leap_state;
	  }

	  /* Get the remembered state. */
	  leap_state = packet_state->info;

	  if (tree) {

	    if        (leap_state==1) {
	      proto_tree_add_text(eap_tree, tvb, offset, count,
				  "Peer Challenge [8] Random Value:\"%s\"",
				  tvb_bytes_to_str(tvb, offset, count));
	    } else if (leap_state==2) {
	      proto_tree_add_text(eap_tree, tvb, offset, count,
				  "Peer Response [24] NtChallengeResponse(%s)",
				  tvb_bytes_to_str(tvb, offset, count));
	    } else if (leap_state==3) {
	      proto_tree_add_text(eap_tree, tvb, offset, count,
				  "AP Challenge [8] Random Value:\"%s\"",
				  tvb_bytes_to_str(tvb, offset, count));
	    } else if (leap_state==4) {
	      proto_tree_add_text(eap_tree, tvb, offset, count,
				  "AP Response [24] ChallengeResponse(%s)",
				  tvb_bytes_to_str(tvb, offset, count));
	    } else {
	      proto_tree_add_text(eap_tree, tvb, offset, count,
				"Data (%d byte%s): \"%s\"",
				count, plurality(count, "", "s"),
				tvb_bytes_to_str(tvb, offset, count));
	    }

	  } /* END: if (tree) */

	  offset += count;

	  /* Name    (Length-(8+Count)) */
	  namesize = eap_len - (8+count);
	  if (tree) {
	    proto_tree_add_text(eap_tree, tvb, offset, namesize,
				"Name (%d byte%s): %s",
				namesize, plurality(count, "", "s"),
				tvb_format_text(tvb, offset, namesize));
	  }
	}

	break; /* EAP_TYPE_LEAP */
      /*********************************************************************
              EAP-MSCHAPv2 - draft-kamath-pppext-eap-mschapv2-00.txt
      **********************************************************************/
      case EAP_TYPE_MSCHAPV2:
	if (tree)
	  dissect_eap_mschapv2(eap_tree, tvb, offset, size);
	break; /* EAP_TYPE_MSCHAPV2 */
      /*********************************************************************
              EAP-SIM - draft-haverinen-pppext-eap-sim-13.txt
      **********************************************************************/
      case EAP_TYPE_SIM:
	if (tree)
	  dissect_eap_sim(eap_tree, tvb, offset, size);
	break; /* EAP_TYPE_SIM */
      /*********************************************************************
              EAP-AKA - draft-arkko-pppext-eap-aka-12.txt
      **********************************************************************/
      case EAP_TYPE_AKA:
	  case EAP_TYPE_AKA_PRIME:
	if (tree)
	  dissect_eap_aka(eap_tree, tvb, offset, size);
	break; /* EAP_TYPE_AKA */
      /*********************************************************************
              EAP Expanded Type
      **********************************************************************/
      case EAP_TYPE_EXT:
	if (tree) {
	  proto_item *expti = NULL;
	  proto_tree *exptree = NULL;

	  expti   = proto_tree_add_text(eap_tree, tvb, offset, size, "Expanded Type");
	  exptree = proto_item_add_subtree(expti, ett_eap_exp_attr);
	  dissect_exteap(exptree, tvb, offset, size, pinfo);
	}
	break;
      /*********************************************************************
      **********************************************************************/
      default:
        if (tree) {
	  proto_tree_add_text(eap_tree, tvb, offset, size,
			      "Type-Data (%d byte%s) Value: %s",
			      size, plurality(size, "", "s"),
			      tvb_bytes_to_str(tvb, offset, size));
	}
	break;
      /*********************************************************************
      **********************************************************************/
      } /* switch (eap_type) */

    }

  } /* switch (eap_code) */

  return tvb_length(tvb);
}

void
proto_register_eap(void)
{
  static hf_register_info hf[] = {
	{ &hf_eap_code, {
		"Code", "eap.code", FT_UINT8, BASE_DEC,
		VALS(eap_code_vals), 0x0, NULL, HFILL }},
	{ &hf_eap_identifier, {
		"Id", "eap.id", FT_UINT8, BASE_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_eap_len, {
		"Length", "eap.len", FT_UINT16, BASE_DEC,
		NULL, 0x0, NULL, HFILL }},
	{ &hf_eap_type, {
		"Type", "eap.type", FT_UINT8, BASE_DEC,
		VALS(eap_type_vals), 0x0, NULL, HFILL }},
	{ &hf_eap_type_nak, {
		"Desired Auth Type", "eap.desired_type", FT_UINT8, BASE_DEC,
		VALS(eap_type_vals), 0x0, NULL, HFILL }},
	{ &hf_eaptls_fragment,
	  { "EAP-TLS Fragment", "eaptls.fragment",
		FT_FRAMENUM, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},
	{ &hf_eaptls_fragments,
	  { "EAP-TLS Fragments", "eaptls.fragments",
	        FT_NONE, BASE_NONE, NULL, 0x0,
	        NULL, HFILL }},
	{ &hf_eaptls_fragment_overlap,
	  { "Fragment overlap",	"eaptls.fragment.overlap",
		FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		"Fragment overlaps with other fragments", HFILL }},
	{ &hf_eaptls_fragment_overlap_conflict,
	  { "Conflicting data in fragment overlap",	"eaptls.fragment.overlap.conflict",
		FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		"Overlapping fragments contained conflicting data", HFILL }},
	{ &hf_eaptls_fragment_multiple_tails,
	  { "Multiple tail fragments found",	"eaptls.fragment.multipletails",
		FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		"Several tails were found when defragmenting the packet", HFILL }},
	{ &hf_eaptls_fragment_too_long_fragment,
	  { "Fragment too long",	"eaptls.fragment.toolongfragment",
		FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		"Fragment contained data past end of packet", HFILL }},
	{ &hf_eaptls_fragment_error,
	  { "Defragmentation error", "eaptls.fragment.error",
		FT_FRAMENUM, BASE_NONE, NULL, 0x0,
		"Defragmentation error due to illegal fragments", HFILL }},
	{ &hf_eaptls_fragment_count,
	  { "Fragment count", "eaptls.fragment.count",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		"The total length of the reassembled payload", HFILL }},
	{ &hf_eaptls_reassembled_length,
	  { "Reassembled EAP-TLS length", "eaptls.reassembled.length",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		"The total length of the reassembled payload", HFILL }},

	/* Expanded type fields */
	{ &hf_eapext_vendorid,
	  { "Vendor Id", "eap.ext.vendor_id",
	    FT_UINT16, BASE_HEX, VALS(eapext_vendorid_vals), 0x0,
	    NULL, HFILL }},
	{ &hf_eapext_vendortype,
	  { "Vendor Type", "eap.ext.vendor_type",
	    FT_UINT8, BASE_HEX, VALS(eapext_vendortype_vals), 0x0,
	    NULL, HFILL }}

  };
  static gint *ett[] = {
	&ett_eap,
	&ett_eaptls_fragment,
	&ett_eaptls_fragments,
	&ett_eap_sim_attr,
	&ett_eap_aka_attr,
	&ett_eap_exp_attr
  };

  proto_eap = proto_register_protocol("Extensible Authentication Protocol",
				      "EAP", "eap");
  proto_register_field_array(proto_eap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  new_register_dissector("eap", dissect_eap, proto_eap);
  register_init_routine(eaptls_defragment_init);
}

void
proto_reg_handoff_eap(void)
{
  dissector_handle_t eap_handle;

  /*
   * Get a handle for the SSL/TLS dissector.
   */
  ssl_handle = find_dissector("ssl");

  eap_handle = find_dissector("eap");
  dissector_add_uint("ppp.protocol", PPP_EAP, eap_handle);
}
