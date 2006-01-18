/* packet-snmp.c
 * Routines for SNMP (simple network management protocol)
 * Copyright (C) 1998 Didier Jorand
 *
 * See RFC 1157 for SNMPv1.
 *
 * See RFCs 1901, 1905, and 1906 for SNMPv2c.
 *
 * See RFCs 1905, 1906, 1909, and 1910 for SNMPv2u [historic].
 *
 * See RFCs 2570-2576 for SNMPv3
 * Updated to use the asn2eth compiler made by Tomas Kukosa
 * Copyright (C) 2005 Anders Broman [AT] ericsson.com
 *
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 *
 * Some stuff from:
 *
 * GXSNMP -- An snmp mangament application
 * Copyright (C) 1998 Gregory McLean & Jochen Friedrich
 * Beholder RMON ethernet network monitor,Copyright (C) 1993 DNPAP group
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

#include <stdio.h>
#include <string.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/conversation.h>
#include "etypes.h"
#include <epan/prefs.h>
#include <epan/sminmpec.h>
#include <epan/emem.h>
#include "packet-ipx.h"
#include "packet-hpext.h"


#include "packet-ber.h"

#ifdef HAVE_SOME_SNMP

#ifdef HAVE_NET_SNMP
# include <net-snmp/net-snmp-config.h>
# include <net-snmp/mib_api.h>
# include <net-snmp/library/default_store.h>
# include <net-snmp/config_api.h>
#else /* HAVE_NET_SNMP */
# include <ucd-snmp/ucd-snmp-config.h>
# include <ucd-snmp/asn1.h>
# include <ucd-snmp/snmp_api.h>
# include <ucd-snmp/snmp_impl.h>
# include <ucd-snmp/mib.h>
# include <ucd-snmp/default_store.h>
# include <ucd-snmp/read_config.h>
# include <ucd-snmp/tools.h>
#endif /* HAVE_NET_SNMP */

#ifndef NETSNMP_DS_LIBRARY_ID
# define NETSNMP_DS_LIBRARY_ID DS_LIBRARY_ID
# define NETSNMP_DS_LIB_NO_TOKEN_WARNINGS DS_LIB_NO_TOKEN_WARNINGS
# define NETSNMP_DS_LIB_PRINT_SUFFIX_ONLY DS_LIB_PRINT_SUFFIX_ONLY
# define netsnmp_ds_set_boolean ds_set_boolean
# define netsnmp_ds_set_int ds_set_int
#endif

#ifdef _WIN32
# include <epan/filesystem.h>
#endif /* _WIN32 */

   /*
    * Define values "sprint_realloc_value()" expects.
    */
# define VALTYPE_INTEGER	ASN_INTEGER
# define VALTYPE_COUNTER	ASN_COUNTER
# define VALTYPE_GAUGE		ASN_GAUGE
# define VALTYPE_TIMETICKS	ASN_TIMETICKS
# define VALTYPE_STRING		ASN_OCTET_STR
# define VALTYPE_IPADDR		ASN_IPADDRESS
# define VALTYPE_OPAQUE		ASN_OPAQUE
# define VALTYPE_NSAP		ASN_NSAP
# define VALTYPE_OBJECTID	ASN_OBJECT_ID
# define VALTYPE_BITSTR		ASN_BIT_STR
# define VALTYPE_COUNTER64	ASN_COUNTER64

#endif /* HAVE_SOME_SNMP */

#include "packet-snmp.h"
#include "format-oid.h"

#define PNAME  "Simple Network Management Protocol"
#define PSNAME "SNMP"
#define PFNAME "snmp"

#define UDP_PORT_SNMP		161
#define UDP_PORT_SNMP_TRAP	162
#define TCP_PORT_SNMP		161
#define TCP_PORT_SNMP_TRAP	162
#define TCP_PORT_SMUX		199

/* Initialize the protocol and registered fields */
static int proto_snmp = -1;
static int proto_smux = -1;

/* Default MIB modules to load */
/*
 * XXX - According to Wes Hardaker, we shouldn't do this:
 *       http://www.ethereal.com/lists/ethereal-dev/200412/msg00222.html
 */
#ifdef _WIN32
# define DEF_MIB_MODULES "IP-MIB;IF-MIB;TCP-MIB;UDP-MIB;SNMPv2-MIB;RFC1213-MIB;UCD-SNMP-MIB"
# define IMPORT_SEPARATOR ":"
#else
# define DEF_MIB_MODULES "IP-MIB:IF-MIB:TCP-MIB:UDP-MIB:SNMPv2-MIB:RFC1213-MIB:UCD-SNMP-MIB"
# define IMPORT_SEPARATOR ";"
#endif /* _WIN32 */

static const gchar *mib_modules = DEF_MIB_MODULES;
static gboolean display_oid = TRUE;

/* Subdissector tables */
static dissector_table_t variable_oid_dissector_table;

#define TH_AUTH   0x01
#define TH_CRYPT  0x02
#define TH_REPORT 0x04

/* desegmentation of SNMP-over-TCP */
static gboolean snmp_desegment = TRUE;

/* Global variables */

guint32 MsgSecurityModel;

static dissector_handle_t snmp_handle;
static dissector_handle_t data_handle;

static int hf_snmp_v3_flags_auth = -1;
static int hf_snmp_v3_flags_crypt = -1;
static int hf_snmp_v3_flags_report = -1;

static int hf_snmp_engineid_conform = -1;
static int hf_snmp_engineid_enterprise = -1;
static int hf_snmp_engineid_format = -1;
static int hf_snmp_engineid_ipv4 = -1;
static int hf_snmp_engineid_ipv6 = -1;
static int hf_snmp_engineid_mac = -1;
static int hf_snmp_engineid_text = -1;
static int hf_snmp_engineid_time = -1;
static int hf_snmp_engineid_data = -1;
#include "packet-snmp-hf.c"

static int hf_smux_version = -1;
static int hf_smux_pdutype = -1;

/* Initialize the subtree pointers */
static gint ett_smux = -1;
static gint ett_snmp = -1;
static gint ett_engineid = -1;
static gint ett_msgFlags = -1;

#include "packet-snmp-ett.c"


/* Security Models */

#define SNMP_SEC_ANY			0
#define SNMP_SEC_V1				1
#define SNMP_SEC_V2C			2
#define SNMP_SEC_USM			3

static const value_string sec_models[] = {
	{ SNMP_SEC_ANY,			"Any" },
	{ SNMP_SEC_V1,			"V1" },
	{ SNMP_SEC_V2C,			"V2C" },
	{ SNMP_SEC_USM,			"USM" },
	{ 0,				NULL }
};

/* SMUX PDU types */
#define SMUX_MSG_OPEN 		0
#define SMUX_MSG_CLOSE		1
#define SMUX_MSG_RREQ		2
#define SMUX_MSG_RRSP		3
#define SMUX_MSG_SOUT		4

static const value_string smux_types[] = {
	{ SMUX_MSG_OPEN,	"Open" },
	{ SMUX_MSG_CLOSE,	"Close" },
	{ SMUX_MSG_RREQ,	"Registration Request" },
	{ SMUX_MSG_RRSP,	"Registration Response" },
	{ SMUX_MSG_SOUT,	"Commit Or Rollback" },
	{ 0,			NULL }
};

int oid_to_subid_buf(const guint8 *oid, gint oid_len, subid_t *buf, int buf_len) {
   int i, out_len;
   guint8 byte;
   guint32 value;

   value=0; out_len = 0;
   for (i=0; i<oid_len; i++){
     if (out_len >= buf_len) break;
     byte = oid[i];
     if (i == 0) {
       buf[out_len++] = byte/40;
       buf[out_len++] = byte%40;
       continue;
     }
     value = (value << 7) | (byte & 0x7F);
     if (byte & 0x80) {
       continue;
     }
     buf[out_len++] = value;
     value = 0;
   }

   return out_len;
}

gchar *
format_oid(subid_t *oid, guint oid_length)
{
	char *result;
	int result_len;
	int len;
	unsigned int i;
	char *buf;
#ifdef HAVE_SOME_SNMP
	guchar *oid_string;
	size_t oid_string_len;
	size_t oid_out_len;
#endif

	result_len = oid_length * 22;

#ifdef HAVE_SOME_SNMP
	/*
	 * Get the decoded form of the OID, and add its length to the
	 * length of the result string.
	 *
	 * XXX - check for "sprint_realloc_objid()" failure.
	 * XXX - if we convert this to ep_alloc(), make sure the fourth
	 * argument to sprint_realloc_objid() is FALSE.
	 */
	oid_string_len = 256;
	oid_string = malloc(oid_string_len);
	if (oid_string == NULL)
		return NULL;
	*oid_string = '\0';
	oid_out_len = 0;
	sprint_realloc_objid(&oid_string, &oid_string_len, &oid_out_len, TRUE,
	    oid, oid_length);
	result_len += strlen(oid_string) + 3;
#endif

	result = ep_alloc(result_len + 1);
	buf = result;
	len = g_snprintf(buf, result_len + 1 - (buf-result), "%lu", (unsigned long)oid[0]);
	buf += len;
	for (i = 1; i < oid_length;i++) {
		len = g_snprintf(buf, result_len + 1 - (buf-result), ".%lu", (unsigned long)oid[i]);
		buf += len;
	}

#ifdef HAVE_SOME_SNMP
	/*
	 * Append the decoded form of the OID.
	 */
	g_snprintf(buf, result_len + 1 -(buf-result), " (%s)", oid_string);
	free(oid_string);
#endif

	return result;
}

/* returns the decoded (can be NULL) and non_decoded OID strings,
   returned pointers shall be freed by the caller */
void
new_format_oid(subid_t *oid, guint oid_length,
	       gchar **non_decoded, gchar **decoded)
{
	int non_decoded_len;
	int len;
	unsigned int i;
	char *buf;

#ifdef HAVE_SOME_SNMP
	guchar *oid_string;
	size_t oid_string_len;
	size_t oid_out_len;

	/*
	 * Get the decoded form of the OID, and add its length to the
	 * length of the result string.
	 */

	/*
	 * XXX - if we convert this to ep_alloc(), make sure the fourth
	 * argument to sprint_realloc_objid() is FALSE.
	 */

	oid_string_len = 256;
	oid_string = malloc(oid_string_len);
	if (oid_string != NULL) {
		*oid_string = '\0';
		oid_out_len = 0;
		sprint_realloc_objid(&oid_string, &oid_string_len, &oid_out_len, TRUE,
				     oid, oid_length);
	}
	*decoded = oid_string;
#else
	*decoded = NULL;
#endif

	non_decoded_len = oid_length * 22 + 1;
	*non_decoded = ep_alloc(non_decoded_len);
	buf = *non_decoded;
	len = g_snprintf(buf, non_decoded_len-(buf-*non_decoded), "%lu", (unsigned long)oid[0]);
	buf += len;
	for (i = 1; i < oid_length; i++) {
	  len = g_snprintf(buf, non_decoded_len-(buf-*non_decoded), ".%lu", (unsigned long)oid[i]);
	  buf += len;
	}
}


#define F_SNMP_ENGINEID_CONFORM 0x80
#define SNMP_ENGINEID_RFC1910 0x00
#define SNMP_ENGINEID_RFC3411 0x01

static const true_false_string tfs_snmp_engineid_conform = {
  "RFC3411 (SNMPv3)",
  "RFC1910 (Non-SNMPv3)"
};

#define SNMP_ENGINEID_FORMAT_IPV4 0x01
#define SNMP_ENGINEID_FORMAT_IPV6 0x02
#define SNMP_ENGINEID_FORMAT_MACADDRESS 0x03
#define SNMP_ENGINEID_FORMAT_TEXT 0x04
#define SNMP_ENGINEID_FORMAT_OCTETS 0x05

static const value_string snmp_engineid_format_vals[] = {
	{ SNMP_ENGINEID_FORMAT_IPV4,	"IPv4 address" },
	{ SNMP_ENGINEID_FORMAT_IPV6,	"IPv6 address" },
	{ SNMP_ENGINEID_FORMAT_MACADDRESS,	"MAC address" },
	{ SNMP_ENGINEID_FORMAT_TEXT,	"Text, administratively assigned" },
	{ SNMP_ENGINEID_FORMAT_OCTETS,	"Octets, administratively assigned" },
	{ 0,   	NULL }
};

/*
 * SNMP Engine ID dissection according to RFC 3411 (SnmpEngineID TC)
 * or historic RFC 1910 (AgentID)
 */
int
dissect_snmp_engineid(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
    proto_item *item = NULL;
    guint8 conformance, format;
    guint32 enterpriseid, seconds;
    nstime_t ts;
    int len_remain = len;

    /* first bit: engine id conformance */
    if (len_remain<4) return offset;
    conformance = ((tvb_get_guint8(tvb, offset)>>7) && 0x01);
    proto_tree_add_item(tree, hf_snmp_engineid_conform, tvb, offset, 1, FALSE);

    /* 4-byte enterprise number/name */
    if (len_remain<4) return offset;
    enterpriseid = tvb_get_ntohl(tvb, offset);
    if (conformance)
      enterpriseid -= 0x80000000; /* ignore first bit */
    proto_tree_add_uint(tree, hf_snmp_engineid_enterprise, tvb, offset, 4, enterpriseid);
    offset+=4;
    len_remain-=4;

    switch(conformance) {

    case SNMP_ENGINEID_RFC1910:
      /* 12-byte AgentID w/ 8-byte trailer */
      if (len_remain==8) {
	proto_tree_add_text(tree, tvb, offset, 8, "AgentID Trailer: 0x%s",
			    tvb_bytes_to_str(tvb, offset, 8));
	offset+=8;
	len_remain-=8;
      } else {
	proto_tree_add_text(tree, tvb, offset, len_remain, "<Data not conforming to RFC1910>");
	return offset;
      }
      break;

    case SNMP_ENGINEID_RFC3411: /* variable length: 5..32 */

      /* 1-byte format specifier */
      if (len_remain<1) return offset;
      format = tvb_get_guint8(tvb, offset);
      item = proto_tree_add_uint_format(tree, hf_snmp_engineid_format, tvb, offset, 1, format, "Engine ID Format: %s (%d)",
			  val_to_str(format, snmp_engineid_format_vals, "Reserved/Enterprise-specific"), format);
      offset+=1;
      len_remain-=1;

      switch(format) {
      case SNMP_ENGINEID_FORMAT_IPV4:
	/* 4-byte IPv4 address */
	if (len_remain==4) {
	  proto_tree_add_item(tree, hf_snmp_engineid_ipv4, tvb, offset, 4, FALSE);
	  offset+=4;
	  len_remain=0;
	}
	break;
      case SNMP_ENGINEID_FORMAT_IPV6:
	/* 16-byte IPv6 address */
	if (len_remain==16) {
	  proto_tree_add_item(tree, hf_snmp_engineid_ipv6, tvb, offset, 16, FALSE);
	  offset+=16;
	  len_remain=0;
	}
	break;
      case SNMP_ENGINEID_FORMAT_MACADDRESS:
	/* 6-byte MAC address */
	if (len_remain==6) {
	  proto_tree_add_item(tree, hf_snmp_engineid_mac, tvb, offset, 6, FALSE);
	  offset+=6;
	  len_remain=0;
	}
	break;
      case SNMP_ENGINEID_FORMAT_TEXT:
	/* max. 27-byte string, administratively assigned */
	if (len_remain<=27) {
	  proto_tree_add_item(tree, hf_snmp_engineid_text, tvb, offset, len_remain, FALSE);
	  offset+=len_remain;
	  len_remain=0;
	}
	break;
      case 128:
	/* most common enterprise-specific format: (ucd|net)-snmp random */
	if ((enterpriseid==2021)||(enterpriseid==8072)) {
	  proto_item_append_text(item, (enterpriseid==2021) ? ": UCD-SNMP Random" : ": Net-SNMP Random");
	  /* demystify: 4B random, 4B epoch seconds */
	  if (len_remain==8) {
	    proto_tree_add_item(tree, hf_snmp_engineid_data, tvb, offset, 4, FALSE);
	    seconds = tvb_get_letohl(tvb, offset+4);
	    ts.secs = seconds;
	    proto_tree_add_time_format(tree, hf_snmp_engineid_time, tvb, offset+4, 4,
                                  &ts, "Engine ID Data: Creation Time: %s",
                                  abs_time_secs_to_str(seconds));
	    offset+=8;
	    len_remain=0;
	  }
	}
	break;
      case SNMP_ENGINEID_FORMAT_OCTETS:
      default:
	/* max. 27 bytes, administratively assigned or unknown format */
	if (len_remain<=27) {
	  proto_tree_add_item(tree, hf_snmp_engineid_data, tvb, offset, len_remain, FALSE);
	  offset+=len_remain;
	  len_remain=0;
	}
	break;
      }
    }

    if (len_remain>0) {
      proto_tree_add_text(tree, tvb, offset, len_remain, "<Data not conforming to RFC3411>");
      offset+=len_remain;
    }
    return offset;
}

#include "packet-snmp-fn.c"

guint
dissect_snmp_pdu(tvbuff_t *tvb, int offset, packet_info *pinfo,
    proto_tree *tree, int proto, gint ett, gboolean is_tcp)
{

	guint length_remaining;
	gint8 class;
	gboolean pc, ind = 0;
	gint32 tag;
	guint32 len;
	guint message_length;
	int start_offset = offset;
	guint32 version = 0;

	proto_tree *snmp_tree = NULL;
	proto_item *item = NULL;

	/*
	 * This will throw an exception if we don't have any data left.
	 * That's what we want.  (See "tcp_dissect_pdus()", which is
	 * similar, but doesn't have to deal with ASN.1.
	 * XXX - can we make "tcp_dissect_pdus()" provide enough
	 * information to the "get_pdu_len" routine so that we could
	 * have that routine deal with ASN.1, and just use
	 * "tcp_dissect_pdus()"?)
	 */
	length_remaining = tvb_ensure_length_remaining(tvb, offset);

	/* NOTE: we have to parse the message piece by piece, since the
	 * capture length may be less than the message length: a 'global'
	 * parsing is likely to fail.
	 */

	/*
	 * If this is SNMP-over-TCP, we might have to do reassembly
	 * in order to read the "Sequence Of" header.
	 */
	if (is_tcp && snmp_desegment && pinfo->can_desegment) {
		/*
		 * This is TCP, and we should, and can, do reassembly.
		 *
		 * Is the "Sequence Of" header split across segment
		 * boundaries?  We requre at least 6 bytes for the
		 * header, which allows for a 4-byte length (ASN.1
		 * BER).
		 */
		if (length_remaining < 6) {
			pinfo->desegment_offset = offset;
			pinfo->desegment_len = 6 - length_remaining;

			/*
			 * Return 0, which means "I didn't dissect anything
			 * because I don't have enough data - we need
			 * to desegment".
			 */
			return 0;
		}
	}

	/*
	 * OK, try to read the "Sequence Of" header; this gets the total
	 * length of the SNMP message.
	 */
	/* Set tree to 0 to not display internakl BER fields if option used.*/
	offset = dissect_ber_identifier(pinfo, 0, tvb, offset, &class, &pc, &tag);
	offset = dissect_ber_length(pinfo, 0, tvb, offset, &len, &ind);

	message_length = len + 2;
	offset = dissect_ber_integer(FALSE, pinfo, 0, tvb, offset, -1, &version);


	/*
	 * If this is SNMP-over-TCP, we might have to do reassembly
	 * to get all of this message.
	 */
	if (is_tcp && snmp_desegment && pinfo->can_desegment) {
		/*
		 * Yes - is the message split across segment boundaries?
		 */
		if (length_remaining < message_length) {
			/*
			 * Yes.  Tell the TCP dissector where the data
			 * for this message starts in the data it handed
			 * us, and how many more bytes we need, and
			 * return.
			 */
			pinfo->desegment_offset = start_offset;
			pinfo->desegment_len =
			    message_length - length_remaining;

			/*
			 * Return 0, which means "I didn't dissect anything
			 * because I don't have enough data - we need
			 * to desegment".
			 */
			return 0;
		}
	}

	if (check_col(pinfo->cinfo, COL_PROTOCOL)) {
		col_set_str(pinfo->cinfo, COL_PROTOCOL,
		    proto_get_protocol_short_name(find_protocol_by_id(proto)));
	}

	if (tree) {
		item = proto_tree_add_item(tree, proto, tvb, offset,
		    message_length, FALSE);
		snmp_tree = proto_item_add_subtree(item, ett);
	}

	switch (version){
	case 0: /* v1 */
	case 1: /* v2c */
		offset = dissect_snmp_Message(FALSE , tvb, start_offset, pinfo, snmp_tree, -1);
		break;
	case 2: /* v2u */
		offset = dissect_snmp_Messagev2u(FALSE , tvb, start_offset, pinfo, snmp_tree, -1);
		break;
			/* v3 */
	case 3:
		offset = dissect_snmp_SNMPv3Message(FALSE , tvb, start_offset, pinfo, snmp_tree, -1);
		break;
	default:
		/*
		 * Return the length remaining in the tvbuff, so
		 * if this is SNMP-over-TCP, our caller thinks there's
		 * nothing left to dissect.
		 */
		proto_tree_add_text(snmp_tree, tvb, offset, -1,"Unknown version");
		return length_remaining;
		break;
	}
	return offset;



}

static gint
dissect_snmp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	conversation_t  *conversation;
	int offset;
	gint8 tmp_class;
	gboolean tmp_pc;
	gint32 tmp_tag;
	guint32 tmp_length;
	gboolean tmp_ind;

	/*
	 * See if this looks like SNMP or not. if not, return 0 so
	 * ethereal can try som other dissector instead.
	 */
	/* All SNMP packets are BER encoded and consist of a SEQUENCE
	 * that spans the entire PDU. The first item is an INTEGER that
	 * has the values 0-2 (version 1-3).
	 * if not it is not snmp.
	 */
	/* SNMP starts with a SEQUENCE */
	offset = get_ber_identifier(tvb, 0, &tmp_class, &tmp_pc, &tmp_tag);
	if((tmp_class!=BER_CLASS_UNI)||(tmp_tag!=BER_UNI_TAG_SEQUENCE)){
		return 0;
	}
	/* then comes a length which spans the rest of the tvb */
	offset = get_ber_length(NULL, tvb, offset, &tmp_length, &tmp_ind);
	if(tmp_length!=(guint32)tvb_reported_length_remaining(tvb, offset)){
		return 0;
	}
	/* then comes an INTEGER (version)*/
	offset = get_ber_identifier(tvb, offset, &tmp_class, &tmp_pc, &tmp_tag);
	if((tmp_class!=BER_CLASS_UNI)||(tmp_tag!=BER_UNI_TAG_INTEGER)){
		return 0;
	}
	/* do we need to test that version is 0 - 2 (version1-3) ? */


	/*
	 * The first SNMP packet goes to the SNMP port; the second one
	 * may come from some *other* port, but goes back to the same
	 * IP address and port as the ones from which the first packet
	 * came; all subsequent packets presumably go between those two
	 * IP addresses and ports.
	 *
	 * If this packet went to the SNMP port, we check to see if
	 * there's already a conversation with one address/port pair
	 * matching the source IP address and port of this packet,
	 * the other address matching the destination IP address of this
	 * packet, and any destination port.
	 *
	 * If not, we create one, with its address 1/port 1 pair being
	 * the source address/port of this packet, its address 2 being
	 * the destination address of this packet, and its port 2 being
	 * wildcarded, and give it the SNMP dissector as a dissector.
	 */
	if (pinfo->destport == UDP_PORT_SNMP) {
	  conversation = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst, PT_UDP,
					   pinfo->srcport, 0, NO_PORT_B);
	  if( (conversation == NULL) || (conversation->dissector_handle!=snmp_handle) ){
	    conversation = conversation_new(pinfo->fd->num, &pinfo->src, &pinfo->dst, PT_UDP,
					    pinfo->srcport, 0, NO_PORT2);
	    conversation_set_dissector(conversation, snmp_handle);
	  }
	}

	return dissect_snmp_pdu(tvb, 0, pinfo, tree, proto_snmp, ett_snmp, FALSE);
}
static void
dissect_snmp_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int offset = 0;
	guint message_len;

	while (tvb_reported_length_remaining(tvb, offset) > 0) {
		message_len = dissect_snmp_pdu(tvb, 0, pinfo, tree,
		    proto_snmp, ett_snmp, TRUE);
		if (message_len == 0) {
			/*
			 * We don't have all the data for that message,
			 * so we need to do desegmentation;
			 * "dissect_snmp_pdu()" has set that up.
			 */
			break;
		}
		offset += message_len;
	}
}
static void
dissect_smux_pdu(tvbuff_t *tvb, int offset, packet_info *pinfo,
    proto_tree *tree, int proto, gint ett)
{
	/* FIX ME */
}
static void
dissect_smux(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_smux_pdu(tvb, 0, pinfo, tree, proto_smux, ett_smux);
}
static void
process_prefs(void)
{
#ifdef HAVE_SOME_SNMP
	gchar *tmp_mib_modules;
	static gboolean mibs_loaded = FALSE;

	if (mibs_loaded) {
		/*
		 * Unload the MIBs, as we'll be reloading them based on
		 * the current preference setting.
		 */
		shutdown_mib();	/* unload MIBs */
	}

	/*
	 * Cannot check if MIBS is already set, as it could be set by Ethereal.
	 *
	 * If we have a list of modules to load, put that list in MIBS,
	 * otherwise clear MIBS.
	 */
	if (mib_modules != NULL) {
		tmp_mib_modules = g_strconcat("MIBS=", mib_modules, NULL);
		/*
		 * Try to be clever and replace colons for semicolons under
		 * Windows.  Do the converse on non-Windows systems.  This
		 * handles cases where we've copied a preferences file
		 * between a non-Windows box and a Windows box or upgraded
		 * from an older version of Ethereal under Windows.
		 */
		g_strdelimit(tmp_mib_modules, IMPORT_SEPARATOR, ENV_SEPARATOR_CHAR);

#ifdef _WIN32
		_putenv(tmp_mib_modules);
#else
		putenv(tmp_mib_modules);
#endif /*_WIN32*/
	} else {
#ifdef _WIN32
		_putenv("MIBS");
#else
		putenv("MIBS");
#endif  /* _WIN32 */
	}

	/*
	 * Load the MIBs.
	 */
	register_mib_handlers();
	read_premib_configs();
	init_mib();
	read_configs();
	mibs_loaded = TRUE;
#endif /* HAVE_SOME_SNMP */
}
/*--- proto_register_snmp -------------------------------------------*/
void proto_register_snmp(void) {

#if defined(_WIN32) && defined(HAVE_SOME_SNMP)
	char *mib_path;
	int mib_path_len;
#define MIB_PATH_APPEND "snmp\\mibs"
#endif
	gchar *tmp_mib_modules;

  /* List of fields */
  static hf_register_info hf[] = {
		{ &hf_snmp_v3_flags_auth,
		{ "Authenticated", "snmp.v3.flags.auth", FT_BOOLEAN, 8,
		    TFS(&flags_set_truth), TH_AUTH, "", HFILL }},
		{ &hf_snmp_v3_flags_crypt,
		{ "Encrypted", "snmp.v3.flags.crypt", FT_BOOLEAN, 8,
		    TFS(&flags_set_truth), TH_CRYPT, "", HFILL }},
		{ &hf_snmp_v3_flags_report,
		{ "Reportable", "snmp.v3.flags.report", FT_BOOLEAN, 8,
		    TFS(&flags_set_truth), TH_REPORT, "", HFILL }},
		{ &hf_snmp_engineid_conform, {
		    "Engine ID Conformance", "snmp.engineid.conform", FT_BOOLEAN, 8,
		    TFS(&tfs_snmp_engineid_conform), F_SNMP_ENGINEID_CONFORM, "Engine ID RFC3411 Conformance", HFILL }},
		{ &hf_snmp_engineid_enterprise, {
		    "Engine Enterprise ID", "snmp.engineid.enterprise", FT_UINT32, BASE_DEC,
		    VALS(sminmpec_values), 0, "Engine Enterprise ID", HFILL }},
		{ &hf_snmp_engineid_format, {
		    "Engine ID Format", "snmp.engineid.format", FT_UINT8, BASE_DEC,
		    VALS(snmp_engineid_format_vals), 0, "Engine ID Format", HFILL }},
		{ &hf_snmp_engineid_ipv4, {
		    "Engine ID Data: IPv4 address", "snmp.engineid.ipv4", FT_IPv4, BASE_NONE,
		    NULL, 0, "Engine ID Data: IPv4 address", HFILL }},
		{ &hf_snmp_engineid_ipv6, {
		    "Engine ID Data: IPv6 address", "snmp.engineid.ipv6", FT_IPv6, BASE_NONE,
		    NULL, 0, "Engine ID Data: IPv6 address", HFILL }},
		{ &hf_snmp_engineid_mac, {
		    "Engine ID Data: MAC address", "snmp.engineid.mac", FT_ETHER, BASE_NONE,
		    NULL, 0, "Engine ID Data: MAC address", HFILL }},
		{ &hf_snmp_engineid_text, {
		    "Engine ID Data: Text", "snmp.engineid.text", FT_STRING, BASE_NONE,
		    NULL, 0, "Engine ID Data: Text", HFILL }},
		{ &hf_snmp_engineid_time, {
		    "Engine ID Data: Time", "snmp.engineid.time", FT_ABSOLUTE_TIME, BASE_NONE,
		    NULL, 0, "Engine ID Data: Time", HFILL }},
		{ &hf_snmp_engineid_data, {
		    "Engine ID Data", "snmp.engineid.data", FT_BYTES, BASE_HEX,
		    NULL, 0, "Engine ID Data", HFILL }},

#include "packet-snmp-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
	  &ett_snmp,
	  &ett_engineid,
	  &ett_msgFlags,

#include "packet-snmp-ettarr.c"
  };
	module_t *snmp_module;

  #ifdef HAVE_SOME_SNMP

#ifdef _WIN32
	/* Set MIBDIRS so that the SNMP library can find its mibs. */
	/* XXX - Should we set MIBS or MIBFILES as well? */
	mib_path_len=strlen(get_datafile_dir()) + strlen(MIB_PATH_APPEND) + 20;
	mib_path = ep_alloc (mib_path_len);
	g_snprintf (mib_path, mib_path_len, "MIBDIRS=%s\\%s", get_datafile_dir(), MIB_PATH_APPEND);
	/* Amazingly enough, Windows does not provide setenv(). */
	if (getenv("MIBDIRS") == NULL)
		_putenv(mib_path);

#endif	/* _WIN32 */

	/*
	 * Suppress warnings about unknown tokens - we aren't initializing
	 * UCD SNMP in its entirety, we're just initializing the
	 * MIB-handling part because that's all we're using, which
	 * means that entries in the configuration file for other
	 * pars of the library will not be handled, and we don't want
	 * the config file reading code to whine about that.
	 */
	netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID,
                               NETSNMP_DS_LIB_NO_TOKEN_WARNINGS, TRUE);
	netsnmp_ds_set_int(NETSNMP_DS_LIBRARY_ID,
                           NETSNMP_DS_LIB_PRINT_SUFFIX_ONLY, 2);
#endif /* HAVE_SOME_SNMP */


  /* Register protocol */
  proto_snmp = proto_register_protocol(PNAME, PSNAME, PFNAME);
  new_register_dissector("snmp", dissect_snmp, proto_snmp);

  /* Register fields and subtrees */
  proto_register_field_array(proto_snmp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));


	/* Register configuration preferences */
	snmp_module = prefs_register_protocol(proto_snmp, process_prefs);
	prefs_register_bool_preference(snmp_module, "display_oid",
		"Show SNMP OID in info column",
		"Whether the SNMP OID should be shown in the info column",
		&display_oid);

	/*
	 * Set the default value of "mib_modules".
	 *
	 * If the MIBS environment variable is set, make its value
	 * the value of "mib_modules", otherwise, set "mib_modules"
	 * to DEF_MIB_MODULES.
	 */
	tmp_mib_modules = getenv("MIBS");
	if (tmp_mib_modules != NULL)
		mib_modules = tmp_mib_modules;
	prefs_register_string_preference(snmp_module, "mib_modules",
	    "MIB modules to load",
	    "List of MIB modules to load (the list is set to environment variable MIBS if the variable is not already set)"
	    "The list must be separated by colons (:) on non-Windows systems and semicolons (;) on Windows systems",
	    &mib_modules);
	prefs_register_bool_preference(snmp_module, "desegment",
	    "Reassemble SNMP-over-TCP messages\nspanning multiple TCP segments",
	    "Whether the SNMP dissector should reassemble messages spanning multiple TCP segments."
	    " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
	    &snmp_desegment);

}


/*--- proto_reg_handoff_snmp ---------------------------------------*/
void proto_reg_handoff_snmp(void) {
	dissector_handle_t snmp_tcp_handle;

	snmp_handle = find_dissector("snmp");

	dissector_add("udp.port", UDP_PORT_SNMP, snmp_handle);
	dissector_add("udp.port", UDP_PORT_SNMP_TRAP, snmp_handle);
	dissector_add("ethertype", ETHERTYPE_SNMP, snmp_handle);
	dissector_add("ipx.socket", IPX_SOCKET_SNMP_AGENT, snmp_handle);
	dissector_add("ipx.socket", IPX_SOCKET_SNMP_SINK, snmp_handle);
	dissector_add("hpext.dxsap", HPEXT_SNMP, snmp_handle);

	snmp_tcp_handle = create_dissector_handle(dissect_snmp_tcp, proto_snmp);
	dissector_add("tcp.port", TCP_PORT_SNMP, snmp_tcp_handle);
	dissector_add("tcp.port", TCP_PORT_SNMP_TRAP, snmp_tcp_handle);

	data_handle = find_dissector("data");

	/*
	 * Process preference settings.
	 *
	 * We can't do this in the register routine, as preferences aren't
	 * read until all dissector register routines have been called (so
	 * that all dissector preferences have been registered).
	 */
	process_prefs();

}

void
proto_register_smux(void)
{
	static hf_register_info hf[] = {
		{ &hf_smux_version,
		{ "Version", "smux.version", FT_UINT8, BASE_DEC, NULL,
		    0x0, "", HFILL }},
		{ &hf_smux_pdutype,
		{ "PDU type", "smux.pdutype", FT_UINT8, BASE_DEC, VALS(smux_types),
		    0x0, "", HFILL }},
	};
	static gint *ett[] = {
		&ett_smux,
	};

	proto_smux = proto_register_protocol("SNMP Multiplex Protocol",
	    "SMUX", "smux");
	proto_register_field_array(proto_smux, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	variable_oid_dissector_table =
	    register_dissector_table("snmp.variable_oid",
	      "SNMP Variable OID", FT_STRING, BASE_NONE);
}

void
proto_reg_handoff_smux(void)
{
	dissector_handle_t smux_handle;

	smux_handle = create_dissector_handle(dissect_smux, proto_smux);
	dissector_add("tcp.port", TCP_PORT_SMUX, smux_handle);
}


