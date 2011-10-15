/* packet-srvloc.c
 * Routines for SRVLOC (Service Location Protocol) packet dissection
 * Copyright 1999, James Coe <jammer@cin.net>
 * Copyright 2002, Brad Hards
 * Updated for TCP segments by Greg Morris <gmorris@novell.com>
 * Copyright 2003, Greg Morris
 *
 * NOTE: This is Alpha software not all features have been verified yet.
 *       In particular I have not had an opportunity to see how it
 *       responds to SRVLOC over TCP.
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Service Location Protocol is RFC 2165
 * Service Location Protocol Version 2 is RFC 2608
 *   - partial support by Brad Hards <bradh@frogmouth.net>
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
#include <stdlib.h>

#include <string.h>
#include <time.h>
#include <glib.h>

#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/prefs.h>
#include <epan/emem.h>
#include "packet-tcp.h"
#include <epan/expert.h>

static gboolean srvloc_desegment = TRUE;
static int proto_srvloc = -1;
static int hf_srvloc_version = -1;
static int hf_srvloc_function = -1;
static int hf_srvloc_pktlen = -1;
static int hf_srvloc_xid = -1;
static int hf_srvloc_langtaglen = -1;
static int hf_srvloc_langtag = -1;
static int hf_srvloc_nextextoff = -1;
static int hf_srvloc_flags_v1 = -1;
static int hf_srvloc_flags_v1_overflow = -1;
static int hf_srvloc_flags_v1_monolingual = -1;
static int hf_srvloc_flags_v1_url_auth = -1;
static int hf_srvloc_flags_v1_attribute_auth = -1;
static int hf_srvloc_flags_v1_fresh = -1;
static int hf_srvloc_error = -1;
static int hf_srvloc_flags_v2 = -1;
static int hf_srvloc_flags_v2_overflow = -1;
static int hf_srvloc_flags_v2_fresh = -1;
static int hf_srvloc_flags_v2_reqmulti = -1;
static int hf_srvloc_error_v2 = -1;
static int hf_srvloc_daadvert_timestamp = -1;
static int hf_srvloc_daadvert_urllen = -1;
static int hf_srvloc_daadvert_url = -1;
static int hf_srvloc_daadvert_scopelistlen = -1;
static int hf_srvloc_daadvert_scopelist = -1;
static int hf_srvloc_daadvert_attrlistlen = -1;
static int hf_srvloc_daadvert_attrlist = -1;
static int hf_srvloc_daadvert_slpspilen = -1;
static int hf_srvloc_daadvert_slpspi = -1;
static int hf_srvloc_daadvert_authcount = -1;
static int hf_srvloc_srvreq_prlistlen = -1;
static int hf_srvloc_srvreq_prlist = -1;
static int hf_srvloc_srvreq_srvtypelen = -1;
static int hf_srvloc_srvreq_srvtypelist = -1;
static int hf_srvloc_srvreq_scopelistlen = -1;
static int hf_srvloc_srvreq_scopelist = -1;
static int hf_srvloc_srvreq_predicatelen = -1;
static int hf_srvloc_srvreq_predicate = -1;
static int hf_srvloc_srvreq_slpspilen = -1;
static int hf_srvloc_srvreq_slpspi = -1;
static int hf_srvloc_srvrply_urlcount = -1;
static int hf_srvloc_srvreg_attrlistlen = -1;
static int hf_srvloc_srvreg_attrlist = -1;
static int hf_srvloc_srvreg_attrauthcount = -1;
static int hf_srvloc_srvreg_srvtypelen = -1;
static int hf_srvloc_srvreg_srvtype = -1;
static int hf_srvloc_srvreg_scopelistlen = -1;
static int hf_srvloc_srvreg_scopelist = -1;
static int hf_srvloc_srvdereg_scopelistlen = -1;
static int hf_srvloc_srvdereg_scopelist = -1;
static int hf_srvloc_srvdereg_taglistlen = -1;
static int hf_srvloc_srvdereg_taglist = -1;
static int hf_srvloc_attrreq_prlistlen  = -1;
static int hf_srvloc_attrreq_prlist  = -1;
static int hf_srvloc_attrreq_urllen  = -1;
static int hf_srvloc_attrreq_url  = -1;
static int hf_srvloc_attrreq_scopelistlen  = -1;
static int hf_srvloc_attrreq_scopelist  = -1;
static int hf_srvloc_attrreq_attrlistlen = -1;
static int hf_srvloc_attrreq_attrlist = -1;
static int hf_srvloc_attrreq_taglistlen  = -1;
static int hf_srvloc_attrreq_taglist  = -1;
static int hf_srvloc_attrreq_slpspilen = -1;
static int hf_srvloc_attrreq_slpspi = -1;
static int hf_srvloc_attrrply_attrlistlen = -1;
static int hf_srvloc_attrrply_attrlist = -1;
static int hf_srvloc_attrrply_attrauthcount = -1;
static int hf_srvloc_srvtypereq_prlistlen = -1;
static int hf_srvloc_srvtypereq_prlist = -1;
static int hf_srvloc_srvtypereq_nameauthlistlen = -1;
static int hf_srvloc_srvtypereq_nameauthlistlenall = -1;
static int hf_srvloc_srvtypereq_nameauthlist = -1;
static int hf_srvloc_srvtypereq_scopelistlen = -1;
static int hf_srvloc_srvtypereq_scopelist = -1;
static int hf_srvloc_srvtyperply_srvtypelen = -1;
static int hf_srvloc_srvtyperply_srvtype = -1;
static int hf_srvloc_srvtyperply_srvtypelistlen = -1;
static int hf_srvloc_srvtyperply_srvtypelist = -1;
static int hf_srvloc_saadvert_urllen = -1;
static int hf_srvloc_saadvert_url = -1;
static int hf_srvloc_saadvert_scopelistlen = -1;
static int hf_srvloc_saadvert_scopelist = -1;
static int hf_srvloc_saadvert_attrlistlen = -1;
static int hf_srvloc_saadvert_attrlist = -1;
static int hf_srvloc_saadvert_authcount = -1;
static int hf_srvloc_authblkv2_bsd = -1;
static int hf_srvloc_authblkv2_len = -1;
static int hf_srvloc_authblkv2_timestamp = -1;
static int hf_srvloc_authblkv2_slpspilen = -1;
static int hf_srvloc_authblkv2_slpspi = -1;
static int hf_srvloc_url_reserved = -1;
static int hf_srvloc_url_lifetime = -1;
static int hf_srvloc_url_urllen = -1;
static int hf_srvloc_url_url = -1;
static int hf_srvloc_url_numauths = -1;
static int hf_srvloc_add_ref_ip = -1;
static int hf_srvloc_srvrply_svcname = -1;


static gint ett_srvloc = -1;
static gint ett_srvloc_attr = -1;
static gint ett_srvloc_flags = -1;


static const true_false_string tfs_srvloc_flags_overflow = {
    "Message will not fit in datagram",
    "Message will fit in a datagram"
};
static const true_false_string tfs_srvloc_flags_v1_monolingual = {
    "Only responses in specified language will be accepted",
    "Responses in any language will be accepted"
};
static const true_false_string tfs_srvloc_flags_v1_url_auth = {
    "URL Authentication Block is present",
    "URL Authentication Block is absent"
};
static const true_false_string tfs_srvloc_flags_v1_attribute_auth = {
    "Attribute Authentication Block is present",
    "Attribute Authentication Block is absent"
};
static const true_false_string tfs_srvloc_flags_fresh = {
    "New Service Registration",
    "Not a new Service Registration"
};
static const true_false_string tfs_srvloc_flags_v2_reqmulti = {
    "Multicast (or broadcast) request",
    "Not multicast or broadcast"
};

#define TCP_PORT_SRVLOC	427
#define UDP_PORT_SRVLOC	427

/* Define function types */

#define SRVREQ		1
#define SRVRPLY		2
#define SRVREG		3
#define SRVDEREG	4
#define SRVACK		5
#define ATTRRQST	6
#define ATTRRPLY	7
#define DAADVERT	8
#define SRVTYPERQST	9
#define	SRVTYPERPLY	10
#define SAADVERT        11 /* SLPv2, section 8 */

/* Create protocol header structure */

/* bradh: looks like never used. */
/* bradh: comment it out for now since it doesn't work for v2
struct srvloc_hdr {
    guint8	version;
    guint8	function;
    guint16	length;
    guint8	flags;
    guint8	dialect;
    guchar	language[2];
    guint16	encoding;
    guint16	xid;
};
*/

/* List to resolve function numbers to names */

static const value_string srvloc_functions[] = {
    { SRVREQ, "Service Request" },
    { SRVRPLY, "Service Reply" },
    { SRVREG, "Service Registration" },
    { SRVDEREG, "Service Deregister" },
    { SRVACK, "Service Acknowledge" },
    { ATTRRQST, "Attribute Request" },
    { ATTRRPLY, "Attribute Reply" },
    { DAADVERT, "DA Advertisement" },
    { SRVTYPERQST, "Service Type Request" },
    { SRVTYPERPLY, "Service Type Reply" },
    { SAADVERT, "SA Advertisement" }, /* v2 only */
    { 0, NULL }
};

/* List to resolve flag values to names */


/* Define flag masks */

#define FLAG_O		0x80
#define FLAG_M		0x40
#define FLAG_U		0x20
#define FLAG_A		0x10
#define FLAG_F		0x08

/* it all changes for Version 2 */
#define FLAG_O_V2       0x8000
#define FLAG_F_V2       0x4000
#define FLAG_R_V2       0x2000

/* Define Error Codes  - Version 1*/

#define SUCCESS		0
#define LANG_NOT_SPTD	1
#define PROT_PARSE_ERR	2
#define INVLD_REG	3
#define SCOPE_NOT_SPTD	4
#define CHRSET_NOT_UND	5
#define AUTH_ABSENT	6
#define AUTH_FAILED	7

/* List to resolve error codes to names */

static const value_string srvloc_errs[] = {
    { SUCCESS, "No Error" },
    { LANG_NOT_SPTD, "Language not supported" },
    { PROT_PARSE_ERR, "Protocol parse error" },
    { INVLD_REG, "Invalid registration" },
    { SCOPE_NOT_SPTD, "Scope not supported" },
    { CHRSET_NOT_UND, "Character set not understood" },
    { AUTH_ABSENT, "Authentication absent" },
    { AUTH_FAILED, "Authentication failed" },
    { 0, NULL }
};

/* Define Error Codes for Version 2 */

#define LANGUAGE_NOT_SUPPORTED 	1
#define PARSE_ERROR 		2
#define INVALID_REGISTRATION	3
#define SCOPE_NOT_SUPPORTED	4
#define AUTHENTICATION_UNKNOWN	5
#define AUTHENTICATION_ABSENT	6
#define AUTHENTICATION_FAILED	7
#define VER_NOT_SUPPORTED	9
#define INTERNAL_ERROR		10
#define DA_BUSY_NOW		11
#define OPTION_NOT_UNDERSTOOD	12
#define INVALID_UPDATE		13
#define MSG_NOT_SUPPORTED	14
#define REFRESH_REJECTED	15

static const value_string srvloc_errs_v2[] = {
    { SUCCESS, "No Error" },
    { LANGUAGE_NOT_SUPPORTED, "No data in the requested language" },
    { PARSE_ERROR, "The message fails to obey SLP syntax." },
    { INVALID_REGISTRATION, "The SrvReg has problems" },
    { SCOPE_NOT_SUPPORTED, "Scope list not supported" },
    { AUTHENTICATION_UNKNOWN, "Unsupported SLP SPI." },
    { AUTHENTICATION_ABSENT, "URL and ATTR authentication not provided"},
    { AUTHENTICATION_FAILED, "Authentication error"},
    { VER_NOT_SUPPORTED, "Unsupported version number in message header" },
    { INTERNAL_ERROR, "The DA (or SA) is too sick to respond" },
    { DA_BUSY_NOW, "UA or SA SHOULD retry" },
    { OPTION_NOT_UNDERSTOOD, "Unknown option from the mandatory range"},
    { INVALID_UPDATE, "Invalid SrvReg" },
    { MSG_NOT_SUPPORTED, "No support for AttrRqst or SrvTypeRqst" },
    { REFRESH_REJECTED, "SrvReg sent too soon"},
    { 0, NULL }
};

/*
 * Character encodings.
 * This is a small subset of what's in
 *
 *	http://www.iana.org/assignments/character-sets
 *
 * XXX - we should do something useful with this, i.e. properly
 * handle strings based on the character set they're in.
 *
 * XXX - what does "properly handle strings" mean?  How do we know
 * what character set the terminal can handle (for tty-based code)
 * or the GUI can handle (for GUI code)?
 *
 * XXX - the Wireshark core really should be what does all the
 * character set handling for strings, and it should be stuck with
 * the task of figuring out how to properly handle them.
 */
#define CHARSET_ASCII		3
#define CHARSET_ISO_10646_UTF_1	27
#define CHARSET_ISO_646_BASIC	28
#define CHARSET_ISO_646_IRV	30
#define CHARSET_ISO_8859_1	4
#define CHARSET_ISO_10646_UCS_2	1000	/* a/k/a Unicode */
#define CHARSET_UTF_7		1012
#define CHARSET_UTF_8		106

static const value_string charsets[] = {
	{ CHARSET_ASCII, "US-ASCII" },
	{ CHARSET_ISO_10646_UTF_1, "ISO 10646 UTF-1" },
	{ CHARSET_ISO_646_BASIC, "ISO 646 basic:1983" },
	{ CHARSET_ISO_646_IRV, "ISO 646 IRV:1983" },
	{ CHARSET_ISO_8859_1, "ISO 8859-1" },
	{ CHARSET_ISO_10646_UCS_2, "Unicode" },
	{ CHARSET_UTF_7, "UTF-7" },
	{ CHARSET_UTF_8, "UTF-8" },
	{ 0, NULL }
};

static int
dissect_authblk(tvbuff_t *tvb, int offset, proto_tree *tree)
{
    struct tm 	*stamp;
    time_t 	seconds;
    double 	floatsec;
    guint16 	length;

    seconds = tvb_get_ntohl(tvb, offset) - 2208988800ul;
    stamp = gmtime(&seconds);
    if (stamp != NULL) {
      floatsec = stamp->tm_sec + tvb_get_ntohl(tvb, offset + 4) / 4294967296.0;
      proto_tree_add_text(tree, tvb, offset, 8,
                          "Timestamp: %04d-%02d-%02d %02d:%02d:%07.4f UTC",
                          stamp->tm_year + 1900, stamp->tm_mon + 1,
                          stamp->tm_mday, stamp->tm_hour, stamp->tm_min,
                          floatsec);
    } else {
      proto_tree_add_text(tree, tvb, offset, 8, "Timestamp not representable");
    }
    proto_tree_add_text(tree, tvb, offset + 8, 2, "Block Structure Descriptor: %u",
			tvb_get_ntohs(tvb, offset + 8));
    length = tvb_get_ntohs(tvb, offset + 10);
    proto_tree_add_text(tree, tvb, offset + 10, 2, "Authenticator length: %u",
			length);
    offset += 12;
    proto_tree_add_text(tree, tvb, offset, length, "Authentication block: %s",
			tvb_format_text(tvb, offset, length));
    offset += length;
    return offset;
}

/* SLPv2 version - Needs to be fixed to match RFC2608 sect 9.2*/
static int
dissect_authblk_v2(tvbuff_t *tvb, int offset, proto_tree *tree)
{
    guint16 length;
    nstime_t ts;

    proto_tree_add_item(tree, hf_srvloc_authblkv2_bsd, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_srvloc_authblkv2_len, tvb, offset+2, 2, ENC_BIG_ENDIAN);
    ts.nsecs = 0;
    ts.secs = tvb_get_ntohl(tvb, offset + 4);
    proto_tree_add_time(tree, hf_srvloc_authblkv2_timestamp, tvb, offset+4, 4, &ts);
    length = tvb_get_ntohs(tvb, offset + 8);
    proto_tree_add_uint(tree, hf_srvloc_authblkv2_slpspilen, tvb, offset + 8, 2, length);
    offset += 10;
    proto_tree_add_item(tree, hf_srvloc_authblkv2_slpspi, tvb, offset, length, ENC_ASCII|ENC_NA);
    offset += length;
    /* add code in here to handle Structured Authentication Block */
    return offset;
}

static int
dissect_attrauthblk_v2(tvbuff_t *tvb _U_, int offset, proto_tree *tree _U_)
{
    /* add code in here to handle attribute authentication */
    return offset;
}

static void
add_v1_string(proto_tree *tree, int hf, tvbuff_t *tvb, int offset, int length,
    guint16 encoding)
{
        char *unicode_str;

        switch (encoding) {

        case CHARSET_ISO_10646_UCS_2:
                unicode_str = tvb_get_ephemeral_faked_unicode(tvb, offset, length/2, FALSE);
                proto_tree_add_string(tree, hf, tvb, offset, length,
                                    unicode_str);
                break;

        default:
                proto_tree_add_item(tree, hf, tvb, offset, length, TRUE);
                break;
        }
}

/*
 * XXX - is this trying to guess the byte order?
 *
 *	http://www.iana.org/assignments/character-sets
 *
 * says of ISO-10646-UCS-2, which has the code 1000 (this routine is used
 * with CHARSET_ISO_10646_UCS_2, which is #defined to be 1000):
 *
 *	this needs to specify network byte order: the standard
 *	does not specify (it is a 16-bit integer space)
 *
 * Does that mean that in SRVLOC, ISO-10646-UCS-2 is always big-endian?
 * If so, can we just use "tvb_get_ephemeral_faked_unicode()" and be
 * done with it?
 *
 * XXX - this is also used with CHARSET_UTF_8.  Is that a cut-and-pasteo?
 */
static guint8*
unicode_to_bytes(tvbuff_t *tvb, int offset, int length, gboolean endianness)
{
  const guint8	*ascii_text = tvb_get_ephemeral_string(tvb, offset, length);
  int	i, j=0;
  guint8	c_char, c_char1;
  guint8	*byte_array;

  /* XXX - Is this the correct behavior? */
  if (length < 1)
    return "";

  if (endianness) {
      byte_array = ep_alloc(length*2 + 1);
      for (i = length; i > 0; i--) {
        c_char = ascii_text[i];
        if (c_char != 0) {
            i--;
            c_char1 = ascii_text[i];
            if (c_char1 == 0) {
                i--;
                c_char1 = ascii_text[i];
            }
            byte_array[j] = c_char1;
            j++;
            byte_array[j] = c_char;
            j++;
        }
      }
  }
  else
  {
      byte_array = ep_alloc(length + 1);
      for (i = 0; i < length; i++) {
        c_char = ascii_text[i];
        if (c_char != 0) {
            byte_array[j] = c_char;
            j++;
        }
      }
  }

  byte_array[j]=0;
  return byte_array;
}

/*
 * Format of x-x-x-xxxxxxxx. Each of these entries represents the service binding to UDP, TCP, or IPX.
 * The first digit is the protocol family: 2 for TCP/UPD, 6 for IPX.
 * The second digit is the socket type: 1 for socket stream (TCP), 2 for datagram (UDP and IPX).
 * The third is the protocol: 6 for TCP, 17 for UDP, and 1000 for IPX.
 * Last is the IP address, in hex, of the interface that is registered (or, in the case of IPX, an IPX network number).
 *
 * OpenSLP supports multiple attribute replies so we need to parse the attribute name and then decode accourdingly.
 * We currently only parse the (non-utf8) attributes:
 * svcname
 * svcaddr
*/
static void
attr_list(proto_tree *tree, int hf, tvbuff_t *tvb, int offset, int length,
    guint16 encoding)
{
    char    *attr_type;
    int     i, svc, ss, type_len, foffset=offset;
    guint32 prot;
    guint8  *byte_value;
    proto_item 	*ti;
    proto_tree 	*srvloc_tree;
    char *tmp;

    static const value_string srvloc_svc[] = {
        { 50, "TCP/UDP" },
        { 54, "IPX" },
        { 0, NULL }
    };

    static const value_string srvloc_ss[] = {
        { 49, "Socket" },
        { 50, "Datagram" },
        { 0, NULL }
    };

    static const value_string srvloc_prot[] = {
        { 54, "TCP" },
        { 17, "UDP" },
        { 1000, "IPX" },
        { 0, NULL }
    };

    switch (encoding) {

    case CHARSET_ISO_10646_UCS_2:
        while (offset+2<length) {
            offset += 2;
            /* If the length passed is longer then the actual payload then this must be an incomplete packet. */
            if (tvb_length_remaining(tvb, 4)<length) {
                proto_tree_add_text(tree, tvb, offset, -1, "Status: Too much data to pass inside this protocol. Resubmit request using a streaming protocol like TCP.");
                proto_tree_add_text(tree, tvb, offset, -1, "Note: Protocol dissection is aborted due to packet overflow. See overflow flag.");
                break;
            }
            /* Parse the attribute name */
            tmp = tvb_get_ephemeral_faked_unicode(tvb, offset, (length-offset)/2, FALSE);
            type_len = (int)strcspn(tmp, "=");
            attr_type = tvb_get_ephemeral_faked_unicode(tvb, offset, type_len, FALSE);
            proto_tree_add_string(tree, hf, tvb, offset, type_len*2, attr_type);
            offset += (type_len*2)+2;
            /* If this is the attribute svcname */
            if (strcmp(attr_type, "svcname-ws")==0) {
                tmp = tvb_get_ephemeral_faked_unicode(tvb, offset, (length-offset)/2, FALSE);
                type_len = (int)strcspn(tmp, ")");
                add_v1_string(tree, hf_srvloc_srvrply_svcname, tvb, offset, type_len*2, encoding);
                offset += (type_len*2)+4;
                attr_type[0] = '\0';
            }
            /* If this is the attribute svcaddr */
            if (strcmp(attr_type, "svcaddr-ws")==0) {
                i=1;
                for (foffset = offset; foffset<length; foffset += 2) {

                    ti = proto_tree_add_text(tree, tvb, foffset, -1, "Item %d", i);
                    srvloc_tree = proto_item_add_subtree(ti, ett_srvloc_attr);

                    svc = tvb_get_guint8(tvb, foffset+1);
        			proto_tree_add_text(srvloc_tree, tvb, foffset+1, 1,
        				    "Service Type: %s", val_to_str(svc, srvloc_svc, "Unknown"));
                    ss = tvb_get_guint8(tvb, foffset+5);
        			proto_tree_add_text(srvloc_tree, tvb, foffset+5, 1,
        				    "Communication Type: %s", val_to_str(ss, srvloc_ss, "Unknown"));
                    foffset += 9;
                    if (svc == 50) {
                        if (tvb_get_guint8(tvb, foffset)==54) { /* TCP */
                            prot = tvb_get_guint8(tvb, foffset);
                            proto_tree_add_text(srvloc_tree, tvb, foffset, 1,
                                    "Protocol: %s", val_to_str(prot, srvloc_prot, "Unknown"));
                            foffset += 2;
                        }
                        else
                        {
                            byte_value = unicode_to_bytes(tvb, foffset, 4, FALSE); /* UDP */
                            prot = atol(byte_value);
                            proto_tree_add_text(srvloc_tree, tvb, foffset, 4,
                                    "Protocol: %s", val_to_str(prot, srvloc_prot, "Unknown"));
                            foffset += 4;
                        }
                    }
                    else
                    {
                        byte_value = unicode_to_bytes(tvb, foffset, 8, FALSE); /* IPX */
                        prot = atol(byte_value);
                        proto_tree_add_text(srvloc_tree, tvb, foffset, 8,
                                    "Protocol: %s", val_to_str(prot, srvloc_prot, "Unknown"));
                        foffset += 8;
                    }
                    if (svc == 50) {
                        byte_value = unicode_to_bytes(tvb, foffset, 16, TRUE); /* IP Address */
                        sscanf(byte_value,"%x",&prot);
                        proto_tree_add_ipv4(srvloc_tree, hf_srvloc_add_ref_ip, tvb, foffset+2, 16, prot);
                        byte_value = unicode_to_bytes(tvb, foffset+18, 8, FALSE); /* Port */
                        sscanf(byte_value,"%x",&prot);
                        proto_tree_add_text(srvloc_tree, tvb, foffset+18, 8, "Port: %d", prot);
                    }
                    else
                    {
                        byte_value = unicode_to_bytes(tvb, foffset+2, 16, FALSE); /* IPX Network Address */
                        sscanf(byte_value,"%x",&prot);
                        proto_tree_add_text(srvloc_tree, tvb, foffset+2, 16, "Network: %s", byte_value);
                        byte_value = unicode_to_bytes(tvb, foffset+18, 24, FALSE); /* IPX Node Address */
                        sscanf(byte_value,"%x",&prot);
                        proto_tree_add_text(srvloc_tree, tvb, foffset+18, 24, "Node: %s", byte_value);
                        byte_value = unicode_to_bytes(tvb, foffset+42, 8, FALSE);  /* Socket */
                        sscanf(byte_value,"%x",&prot);
                        proto_tree_add_text(srvloc_tree, tvb, foffset+42, 8, "Socket: %s", byte_value);
                    }
                    i++;
                    foffset += 57;
                }
                offset = foffset;
                attr_type[0] = '\0';
            }
            /* If there are no more supported attributes available then abort dissection */
            if (strcmp(attr_type, "svcaddr-ws")!=0 && strcmp(attr_type, "svcname-ws")!=0 && strcmp(attr_type, "\0")!=0) {
                break;
            }
        }
        break;

    case CHARSET_UTF_8:
        type_len = (int)strcspn(tvb_get_ephemeral_string(tvb, offset, length), "=");
        attr_type = unicode_to_bytes(tvb, offset+1, type_len-1, FALSE);
        proto_tree_add_string(tree, hf, tvb, offset+1, type_len-1, attr_type);
        i=1;
        for (foffset = offset + (type_len); foffset<length; foffset++) {

            ti = proto_tree_add_text(tree, tvb, foffset, -1, "Item %d", i);
            srvloc_tree = proto_item_add_subtree(ti, ett_srvloc_attr);

            svc = tvb_get_guint8(tvb, foffset+1);
			proto_tree_add_text(srvloc_tree, tvb, foffset+1, 1,
				    "Service Type: %s", val_to_str(svc, srvloc_svc, "Unknown"));
            ss = tvb_get_guint8(tvb, foffset+3);
			proto_tree_add_text(srvloc_tree, tvb, foffset+3, 1,
				    "Communication Type: %s", val_to_str(ss, srvloc_ss, "Unknown"));
            foffset += 5;
            if (svc == 50) {
                if (tvb_get_guint8(tvb, foffset)==54) { /* TCP */
                    prot = tvb_get_guint8(tvb, foffset);
                    proto_tree_add_text(srvloc_tree, tvb, foffset, 1,
                            "Protocol: %s", val_to_str(prot, srvloc_prot, "Unknown"));
                    foffset += 1;
                }
                else
                {
                    /* UDP */
                    byte_value = unicode_to_bytes(tvb, foffset, 2, FALSE); /* UDP */
                    prot = atol(byte_value);
                    proto_tree_add_text(srvloc_tree, tvb, foffset, 2,
                            "Protocol: %s", val_to_str(prot, srvloc_prot, "Unknown"));
                    foffset += 2;
                }
            }
            else
            {
                byte_value = unicode_to_bytes(tvb, foffset, 4, FALSE); /* IPX */
                prot = atol(byte_value);
                proto_tree_add_text(srvloc_tree, tvb, foffset, 4,
                            "Protocol: %s", val_to_str(prot, srvloc_prot, "Unknown"));
                foffset += 4;
            }
            if (svc == 50) {
                byte_value = unicode_to_bytes(tvb, foffset, 8, TRUE); /* IP Address */
                sscanf(byte_value,"%x",&prot);
                proto_tree_add_ipv4(srvloc_tree, hf_srvloc_add_ref_ip, tvb, foffset+1, 8, prot);
                byte_value = unicode_to_bytes(tvb, foffset+9, 4, FALSE); /* Port */
                sscanf(byte_value,"%x",&prot);
                proto_tree_add_text(srvloc_tree, tvb, foffset+9, 4, "Port: %d", prot);
            }
            else
            {
                byte_value = unicode_to_bytes(tvb, foffset+1, 8, FALSE); /* IPX Network Address */
                sscanf(byte_value,"%x",&prot);
                proto_tree_add_text(srvloc_tree, tvb, foffset+1, 8, "Network: %s", byte_value);
                byte_value = unicode_to_bytes(tvb, foffset+9, 12, FALSE); /* IPX Node Address */
                sscanf(byte_value,"%x",&prot);
                proto_tree_add_text(srvloc_tree, tvb, foffset+9, 12, "Node: %s", byte_value);
                byte_value = unicode_to_bytes(tvb, foffset+21, 4, FALSE);  /* Socket */
                sscanf(byte_value,"%x",&prot);
                proto_tree_add_text(srvloc_tree, tvb, foffset+21, 4, "Socket: %s", byte_value);
            }
            i++;
            foffset += 28;
        }
        break;


    default:
            proto_tree_add_item(tree, hf, tvb, offset, length, TRUE);
            break;
    }
}

static void
attr_list2(proto_tree *tree, int hf, tvbuff_t *tvb, int offset, int length, guint16 encoding _U_)
{
    guint8      *start;
    guint8       c;
    guint32      x;
    guint32      cnt;
    proto_item  *ti;
    proto_tree  *attr_tree;

    /* if we were to decode:
     * For slp, these 9 characters: (),\!<=>~ and 0x00-1F, 0x7f are reserved and must be escaped in the form \HH
     */

    /* create a sub tree for attributes */
    ti = proto_tree_add_item(tree, hf, tvb, offset, length, TRUE);
    attr_tree = proto_item_add_subtree(ti, ett_srvloc_attr);

    /* this will ensure there is a terminating null */
    start = tvb_get_ephemeral_string(tvb, offset, length);

    cnt = 0;
    x = 0;
    c = start[x];
    while (c) {
        if  (c == ',') {
            cnt++; /* Attribute count */
            start[x] = 0;
            proto_tree_add_text(attr_tree, tvb, offset, x, "Item %d: %s", cnt, start);
            offset += x+1;
            start += x+1;
            /* reset string length */
            x = 0;
            c = start[x];
        } else {
            /* increment and get next */
            x++;
            c = start[x];
        }
    }
    /* display anything remaining */
    if (x) {
        cnt++;
        proto_tree_add_text(attr_tree, tvb, offset, x, "Item %d: %s", cnt, start);
    }
}

static int
dissect_url_entry_v1(tvbuff_t *tvb, int offset, proto_tree *tree,
                     guint16 encoding, guint16 flags)
{
    guint16	url_len;

    proto_tree_add_item(tree, hf_srvloc_url_lifetime, tvb, offset, 2,
			ENC_BIG_ENDIAN);
    offset += 2;
    url_len = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(tree, hf_srvloc_url_urllen, tvb, offset, 2,
			url_len);
    offset += 2;
    add_v1_string(tree, hf_srvloc_url_url, tvb, offset, url_len, encoding);
    offset += url_len;
    if ( (flags & FLAG_U) == FLAG_U )
        offset = dissect_authblk(tvb, offset, tree);
    return offset;
}

static int
dissect_url_entry_v2(tvbuff_t *tvb, int offset, proto_tree *tree)
{
    guint8	reserved;
    guint16	url_len;
    guint8	num_auths;

    reserved = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(tree, hf_srvloc_url_reserved, tvb, offset, 1,
			reserved);
    offset += 1;
    proto_tree_add_item(tree, hf_srvloc_url_lifetime, tvb, offset, 2,
			ENC_BIG_ENDIAN);
    offset += 2;
    url_len = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(tree, hf_srvloc_url_urllen, tvb, offset, 2,
			url_len);
    offset += 2;
    proto_tree_add_item(tree, hf_srvloc_url_url, tvb, offset, url_len, ENC_ASCII|ENC_NA);
    offset += url_len;
    num_auths = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(tree, hf_srvloc_url_numauths, tvb, offset, 1,
			num_auths);
    offset += 1;
    while (num_auths > 0) {
	offset = dissect_authblk_v2(tvb, offset, tree);
	num_auths--;
    }
    return offset;
}

/* Packet dissection routine called by tcp & udp when port 427 detected */

static void
dissect_srvloc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int         offset = 0;
    proto_item  *ti, *tf;
    proto_tree  *srvloc_tree, *srvloc_flags;
    guint8      version;
    guint8      function;
    guint16     encoding;
    guint32     length; /* three bytes needed for v2 */
    guint16     flags; /* two byes needed for v2 */
    guint32     count;
    guint32     next_ext_off; /* three bytes, v2 only */
    guint16     lang_tag_len;
    nstime_t    ts;
    proto_item  *expert_item;
    guint16     expert_status;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SRVLOC");

    col_clear(pinfo->cinfo, COL_INFO);

    version = tvb_get_guint8(tvb, offset);
    function = tvb_get_guint8(tvb, offset + 1);

    if (check_col(pinfo->cinfo, COL_INFO))
        col_add_str(pinfo->cinfo, COL_INFO,
            val_to_str(function, srvloc_functions, "Unknown Function (%u)"));

    ti = proto_tree_add_item(tree, proto_srvloc, tvb, offset, -1, FALSE);
    srvloc_tree = proto_item_add_subtree(ti, ett_srvloc);

    proto_tree_add_uint(srvloc_tree, hf_srvloc_version, tvb, offset, 1,
                        version);
    proto_tree_add_uint(srvloc_tree, hf_srvloc_function, tvb, offset + 1, 1,
                        function);
    if (version < 2) {
        length = tvb_get_ntohs(tvb, offset + 2);
        proto_tree_add_uint(srvloc_tree, hf_srvloc_pktlen, tvb, offset + 2, 2,
                            length);
        flags = tvb_get_guint8(tvb, offset + 4);
        tf = proto_tree_add_uint(srvloc_tree, hf_srvloc_flags_v1, tvb, offset + 4, 1,
                                 flags);
        srvloc_flags = proto_item_add_subtree(tf, ett_srvloc_flags);
        proto_tree_add_boolean(srvloc_flags, hf_srvloc_flags_v1_overflow,
                               tvb, offset+4, 1, flags);
        proto_tree_add_boolean(srvloc_flags, hf_srvloc_flags_v1_monolingual,
                               tvb, offset+4, 1, flags);
        proto_tree_add_boolean(srvloc_flags, hf_srvloc_flags_v1_url_auth,
                               tvb, offset+4, 1, flags);
        proto_tree_add_boolean(srvloc_flags, hf_srvloc_flags_v1_attribute_auth,
                               tvb, offset+4, 1, flags);
        proto_tree_add_boolean(srvloc_flags, hf_srvloc_flags_v1_fresh,
                               tvb, offset+4, 1, flags);
        proto_tree_add_text(srvloc_tree, tvb, offset + 5, 1, "Dialect: %u",
                            tvb_get_guint8(tvb, offset + 5));
        proto_tree_add_text(srvloc_tree, tvb, offset + 6, 2, "Language: %s",
                            tvb_format_text(tvb, offset + 6, 2));
        encoding = tvb_get_ntohs(tvb, offset + 8);
        proto_tree_add_text(srvloc_tree, tvb, offset + 8, 2, "Encoding: %u (%s)",
                            encoding,
                            val_to_str(encoding, charsets, "Unknown"));
        proto_tree_add_text(srvloc_tree, tvb, offset + 10, 2, "Transaction ID: %u",
                            tvb_get_ntohs(tvb, offset + 10));
        /* added echo of XID to info colomn by Greg Morris 0ct 14, 2005 */
        if (check_col(pinfo->cinfo, COL_INFO))
            col_append_fstr(pinfo->cinfo, COL_INFO, ", V1 Transaction ID - %u", tvb_get_ntohs(tvb, offset + 10));

        offset += 12;

        switch (function) {

        case SRVREQ:
            length = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint(srvloc_tree, hf_srvloc_srvreq_prlistlen, tvb, offset, 2, length);
            offset += 2;
            add_v1_string(srvloc_tree, hf_srvloc_srvreq_prlist, tvb, offset, length, encoding);
            offset += length;
            length = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint(srvloc_tree, hf_srvloc_srvreq_predicatelen, tvb, offset, 2, length);
            offset += 2;
            add_v1_string(srvloc_tree, hf_srvloc_srvreq_predicate, tvb, offset, length, encoding);
            offset += length;
            break;

        case SRVRPLY:
            expert_item = proto_tree_add_item(srvloc_tree, hf_srvloc_error, tvb, offset, 2, ENC_BIG_ENDIAN);
            expert_status = tvb_get_ntohs(tvb, offset);
            if (expert_status!=0) {
                expert_add_info_format(pinfo, expert_item, PI_RESPONSE_CODE, PI_ERROR, "Error: %s", val_to_str(expert_status, srvloc_errs, "Unknown SRVLOC Error (0x%02x)"));
            }
            offset += 2;
            count = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint(srvloc_tree, hf_srvloc_srvrply_urlcount, tvb, offset, 2, count);
            offset += 2;
            while (count > 0) {
                offset = dissect_url_entry_v1(tvb, offset, srvloc_tree,
                                              encoding, flags);
                count--;
            }
            break;

        case SRVREG:
            offset = dissect_url_entry_v1(tvb, offset, srvloc_tree, encoding,
                                          flags);
            length = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint(srvloc_tree, hf_srvloc_srvreg_attrlistlen, tvb, offset, 2, length);
            offset += 2;
            add_v1_string(srvloc_tree, hf_srvloc_srvreg_attrlist, tvb, offset, length, encoding);
            offset += length;
            if ( (flags & FLAG_A) == FLAG_A )
                offset = dissect_authblk(tvb, offset, srvloc_tree);
            break;

        case SRVDEREG:
            length = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint(tree, hf_srvloc_url_urllen, tvb, offset, 2, length);
            offset += 2;
            add_v1_string(tree, hf_srvloc_url_url, tvb, offset, length, encoding);
            offset += length;
            if ( (flags & FLAG_U) == FLAG_U )
                offset = dissect_authblk(tvb, offset, srvloc_tree);
            length = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint(srvloc_tree, hf_srvloc_srvdereg_taglistlen, tvb, offset, 2, length);
            offset += 2;
            add_v1_string(srvloc_tree, hf_srvloc_srvdereg_taglist, tvb, offset, length, encoding);
            offset += length;
            /*
             * XXX - this was there before, but RFC 2165 doesn't speak
             * of there being an attribute authentication block in
             * a Service Deregister message.  Is that a post-RFC-2165
             * addition?
             */
            if ( (flags & FLAG_A) == FLAG_A )
                offset = dissect_authblk(tvb, offset, srvloc_tree);
            break;

        case SRVACK:
            expert_item = proto_tree_add_item(srvloc_tree, hf_srvloc_error, tvb, offset, 2, ENC_BIG_ENDIAN);
            expert_status = tvb_get_ntohs(tvb, offset);
            if (expert_status!=0) {
                expert_add_info_format(pinfo, expert_item, PI_RESPONSE_CODE, PI_ERROR, "Error: %s", val_to_str(expert_status, srvloc_errs, "Unknown SRVLOC Error (0x%02x)"));
            }
            offset += 2;
            break;

        case ATTRRQST:
            length = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint(srvloc_tree, hf_srvloc_attrreq_prlistlen, tvb, offset, 2, length);
            offset += 2;
            add_v1_string(srvloc_tree, hf_srvloc_attrreq_prlist, tvb, offset, length, encoding);
            offset += length;
            length = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint(srvloc_tree, hf_srvloc_attrreq_urllen, tvb, offset, 2, length);
            offset += 2;
            add_v1_string(srvloc_tree, hf_srvloc_attrreq_url, tvb, offset, length, encoding);
            offset += length;
            length = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint(srvloc_tree, hf_srvloc_attrreq_scopelistlen, tvb, offset, 2, length);
            offset += 2;
            add_v1_string(srvloc_tree, hf_srvloc_attrreq_scopelist, tvb, offset, length, encoding);
            offset += length;
            length = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint(srvloc_tree, hf_srvloc_attrreq_attrlistlen, tvb, offset, 2, length);
            offset += 2;
            add_v1_string(srvloc_tree, hf_srvloc_attrreq_attrlist, tvb, offset, length, encoding);
            offset += length;
            break;

        case ATTRRPLY:
            expert_item = proto_tree_add_item(srvloc_tree, hf_srvloc_error_v2, tvb, offset, 2, ENC_BIG_ENDIAN);
            expert_status = tvb_get_ntohs(tvb, offset);
            if (expert_status!=0) {
                expert_add_info_format(pinfo, expert_item, PI_RESPONSE_CODE, PI_ERROR, "Error: %s", val_to_str(expert_status, srvloc_errs_v2, "Unknown SRVLOC Error (0x%02x)"));
            }
            offset += 2;
            length = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint(srvloc_tree, hf_srvloc_attrrply_attrlistlen, tvb, offset, 2, length);
            if (length > 0) {
                offset += 2;
                attr_list(srvloc_tree, hf_srvloc_attrrply_attrlist, tvb, offset, length, encoding);
                offset += length;
                if ( (flags & FLAG_A) == FLAG_A )
                    offset = dissect_authblk(tvb, offset, srvloc_tree);
            }
            break;

        case DAADVERT:
            expert_item = proto_tree_add_item(srvloc_tree, hf_srvloc_error, tvb, offset, 2, ENC_BIG_ENDIAN);
            expert_status = tvb_get_ntohs(tvb, offset);
            if (expert_status!=0) {
                expert_add_info_format(pinfo, expert_item, PI_RESPONSE_CODE, PI_ERROR, "Error: %s", val_to_str(expert_status, srvloc_errs, "Unknown SRVLOC Error (0x%02x)"));
            }
            offset += 2;
            length = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint(srvloc_tree, hf_srvloc_daadvert_urllen, tvb, offset, 2, length);
            offset += 2;
            add_v1_string(srvloc_tree, hf_srvloc_daadvert_url, tvb, offset, length, encoding);
            offset += length;
            length = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint(srvloc_tree, hf_srvloc_daadvert_scopelistlen, tvb, offset, 2, length);
            offset += 2;
            add_v1_string(srvloc_tree, hf_srvloc_daadvert_scopelist, tvb, offset, length, encoding);
            offset += length;
            break;

        case SRVTYPERQST:
            length = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint(srvloc_tree, hf_srvloc_srvtypereq_prlistlen, tvb, offset, 2, length);
            offset += 2;
            add_v1_string(srvloc_tree, hf_srvloc_srvtypereq_prlist, tvb, offset, length, encoding);
            offset += length;
            length = tvb_get_ntohs(tvb, offset);
            /* Updated by Greg Morris on 1-30-04 */
            if (0xFFFF == length) {
                proto_tree_add_uint(srvloc_tree, hf_srvloc_srvtypereq_nameauthlistlenall, tvb, offset, 2, length);
                offset += 2;
            }
            else
            {
                proto_tree_add_uint(srvloc_tree, hf_srvloc_srvtypereq_nameauthlistlen, tvb, offset, 2, length);
                offset += 2;
                add_v1_string(srvloc_tree, hf_srvloc_srvtypereq_nameauthlist, tvb, offset, length, encoding);
                offset += length;
            }
            length = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint(srvloc_tree, hf_srvloc_srvtypereq_scopelistlen, tvb, offset, 2, length);
            offset += 2;
            add_v1_string(srvloc_tree, hf_srvloc_srvtypereq_scopelist, tvb, offset, length, encoding);
            offset += length;
            break;

        case SRVTYPERPLY:
            expert_item = proto_tree_add_item(srvloc_tree, hf_srvloc_error, tvb, offset, 2, ENC_BIG_ENDIAN);
            expert_status = tvb_get_ntohs(tvb, offset);
            if (expert_status!=0) {
                expert_add_info_format(pinfo, expert_item, PI_RESPONSE_CODE, PI_ERROR, "Error: %s", val_to_str(expert_status, srvloc_errs, "Unknown SRVLOC Error (0x%02x)"));
            }
            offset += 2;
            count = tvb_get_ntohs(tvb, offset);
            proto_tree_add_text(srvloc_tree, tvb, offset, 2, "Service Type Count: %u",
                                count);
            offset += 2;
            while (count > 0) {
                length = tvb_get_ntohs(tvb, offset);
                proto_tree_add_uint(srvloc_tree, hf_srvloc_srvtyperply_srvtypelen, tvb, offset, 2, length);
                offset += 2;
                add_v1_string(srvloc_tree, hf_srvloc_srvtyperply_srvtype, tvb, offset, length, encoding);
                offset += length;
                count--;
            }
            break;

        default:
            expert_item = proto_tree_add_text(srvloc_tree, tvb, offset, -1, "Unknown Function Type");
            expert_add_info_format(pinfo, expert_item, PI_RESPONSE_CODE, PI_ERROR, "Unknown Function Type: %d", function);
        }
    }
    else { /* Version 2 */
        length = tvb_get_ntoh24(tvb, offset + 2);
        proto_tree_add_uint(srvloc_tree, hf_srvloc_pktlen, tvb, offset + 2, 3,
                            length);
        flags = tvb_get_ntohs(tvb, offset + 5);
        tf = proto_tree_add_uint(srvloc_tree, hf_srvloc_flags_v2, tvb, offset + 5, 2,
                                 flags);
        srvloc_flags = proto_item_add_subtree(tf, ett_srvloc_flags);
        proto_tree_add_boolean(srvloc_flags, hf_srvloc_flags_v2_overflow,
                               tvb, offset+5, 1, flags);
        proto_tree_add_boolean(srvloc_flags, hf_srvloc_flags_v2_fresh,
                               tvb, offset+5, 1, flags);
        proto_tree_add_boolean(srvloc_flags, hf_srvloc_flags_v2_reqmulti,
                               tvb, offset+5, 1, flags);

        next_ext_off = tvb_get_ntoh24(tvb, offset + 7);
        proto_tree_add_uint(srvloc_tree, hf_srvloc_nextextoff, tvb, offset + 7, 3,
                            next_ext_off);
        proto_tree_add_uint(srvloc_tree, hf_srvloc_xid, tvb, offset + 10, 2,
                            tvb_get_ntohs(tvb, offset + 10));
        if (check_col(pinfo->cinfo, COL_INFO))
            col_append_fstr(pinfo->cinfo, COL_INFO, ", V2 XID - %u", tvb_get_ntohs(tvb, offset + 10));
        lang_tag_len = tvb_get_ntohs(tvb, offset + 12);
        proto_tree_add_uint(srvloc_tree, hf_srvloc_langtaglen, tvb, offset + 12, 2, lang_tag_len);
        proto_tree_add_item(srvloc_tree, hf_srvloc_langtag, tvb, offset + 14, lang_tag_len, ENC_ASCII|ENC_NA);
        offset += 14+lang_tag_len;

        switch (function) {

        case SRVREQ: /* RFC2608 8.1 */
            length = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint(srvloc_tree, hf_srvloc_srvreq_prlistlen, tvb, offset, 2, length);
            offset += 2;
            if (length) {
                proto_tree_add_item(srvloc_tree, hf_srvloc_srvreq_prlist, tvb, offset, length, ENC_ASCII|ENC_NA);
                offset += length;
            }
            length = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint(srvloc_tree, hf_srvloc_srvreq_srvtypelen, tvb, offset, 2, length);
            offset += 2;
            if (length) {
                proto_tree_add_item(srvloc_tree, hf_srvloc_srvreq_srvtypelist, tvb, offset, length, ENC_ASCII|ENC_NA);
                offset += length;
            }
            length = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint(srvloc_tree, hf_srvloc_srvreq_scopelistlen, tvb, offset, 2, length);
            offset += 2;
            if (length) {
                proto_tree_add_item(srvloc_tree, hf_srvloc_srvreq_scopelist, tvb, offset, length, ENC_ASCII|ENC_NA);
                offset += length;
            }
            length = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint(srvloc_tree, hf_srvloc_srvreq_predicatelen, tvb, offset, 2, length);
            offset += 2;
            if (length) {
                proto_tree_add_item(srvloc_tree, hf_srvloc_srvreq_predicate, tvb, offset, length, ENC_ASCII|ENC_NA);
                offset += length;
            }
            length = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint(srvloc_tree, hf_srvloc_srvreq_slpspilen, tvb, offset, 2, length);
            offset += 2;
            if (length) {
                proto_tree_add_item(srvloc_tree, hf_srvloc_srvreq_slpspi, tvb, offset, length, ENC_ASCII|ENC_NA);
                offset += length;
            }
            break;

        case SRVRPLY: /* RFC2608 8.2 */
            expert_item = proto_tree_add_item(srvloc_tree, hf_srvloc_error_v2, tvb, offset, 2, ENC_BIG_ENDIAN);
            expert_status = tvb_get_ntohs(tvb, offset);
            if (expert_status!=0) {
                expert_add_info_format(pinfo, expert_item, PI_RESPONSE_CODE, PI_ERROR, "Error: %s", val_to_str(expert_status, srvloc_errs_v2, "Unknown SRVLOC Error (0x%02x)"));
            }
            offset += 2;
            count = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint(srvloc_tree, hf_srvloc_srvrply_urlcount, tvb, offset, 2, count);
            offset += 2;
            while (count > 0) {
                offset = dissect_url_entry_v2(tvb, offset, srvloc_tree);
                count--;
            }
            break;

        case SRVREG: /* RFC2608 8.3 */
            offset = dissect_url_entry_v2(tvb, offset, srvloc_tree);
            length = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint(srvloc_tree, hf_srvloc_srvreg_srvtypelen, tvb, offset, 2, length);
            offset += 2;
            if (length) {
                proto_tree_add_item(srvloc_tree, hf_srvloc_srvreg_srvtype, tvb, offset, length, ENC_ASCII|ENC_NA);
                offset += length;
            }
            length = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint(srvloc_tree, hf_srvloc_srvreg_scopelistlen, tvb, offset, 2, length);
            offset += 2;
            if (length) {
                proto_tree_add_item(srvloc_tree, hf_srvloc_srvreg_scopelist, tvb, offset, length, ENC_ASCII|ENC_NA);
                offset += length;
            }
            length = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint(srvloc_tree, hf_srvloc_srvreg_attrlistlen, tvb, offset, 2, length);
            offset += 2;
            if (length) {
                attr_list2(srvloc_tree, hf_srvloc_srvreg_attrlist, tvb, offset, length, CHARSET_UTF_8);
                offset += length;
            }
            count = tvb_get_guint8(tvb, offset);
            proto_tree_add_uint(srvloc_tree, hf_srvloc_srvreg_attrauthcount, tvb, offset, 1, count);
            offset += 1;
            while (count > 0) {
                offset = dissect_attrauthblk_v2(tvb, offset, srvloc_tree);
                count--;
            }
            break;

        case SRVDEREG: /* RFC2608 10.6 */
            length = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint(srvloc_tree, hf_srvloc_srvdereg_scopelistlen, tvb, offset, 2, length);
            offset += 2;
            if (length) {
                proto_tree_add_item(srvloc_tree, hf_srvloc_srvdereg_scopelist, tvb, offset, length, ENC_ASCII|ENC_NA);
                offset += length;
            }
            offset = dissect_url_entry_v2(tvb, offset, srvloc_tree);
            length = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint(srvloc_tree, hf_srvloc_srvdereg_taglistlen, tvb, offset, 2, length);
            offset += 2;
            if (length) {
                proto_tree_add_item(srvloc_tree, hf_srvloc_srvdereg_taglist, tvb, offset, length, ENC_ASCII|ENC_NA);
                offset += length;
            }
            break;

        case SRVACK: /* RFC2608 8.4 */
            expert_item = proto_tree_add_item(srvloc_tree, hf_srvloc_error_v2, tvb, offset, 2, ENC_BIG_ENDIAN);
            expert_status = tvb_get_ntohs(tvb, offset);
            if (expert_status!=0) {
                expert_add_info_format(pinfo, expert_item, PI_RESPONSE_CODE, PI_ERROR, "Error: %s", val_to_str(expert_status, srvloc_errs_v2, "Unknown SRVLOC Error (0x%02x)"));
            }
            offset += 2;
            break;

        case ATTRRQST: /* RFC2608 10.3*/
            length = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint(srvloc_tree, hf_srvloc_attrreq_prlistlen, tvb, offset, 2, length);
            offset += 2;
            if (length) {
                proto_tree_add_item(srvloc_tree, hf_srvloc_attrreq_prlist, tvb, offset, length, ENC_ASCII|ENC_NA);
                offset += length;
            }
            length = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint(srvloc_tree, hf_srvloc_attrreq_urllen, tvb, offset, 2, length);
            offset += 2;
            if (length) {
                proto_tree_add_item(srvloc_tree, hf_srvloc_attrreq_url, tvb, offset, length, ENC_ASCII|ENC_NA);
                offset += length;
            }
            length = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint(srvloc_tree, hf_srvloc_attrreq_scopelistlen, tvb, offset, 2, length);
            offset += 2;
            if (length) {
                proto_tree_add_item(srvloc_tree, hf_srvloc_attrreq_scopelist, tvb, offset, length, ENC_ASCII|ENC_NA);
                offset += length;
            }
            length = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint(srvloc_tree, hf_srvloc_attrreq_taglistlen, tvb, offset, 2, length);
            offset += 2;
            if (length) {
                proto_tree_add_item(srvloc_tree, hf_srvloc_attrreq_taglist, tvb, offset, length, ENC_ASCII|ENC_NA);
                offset += length;
            }
            length = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint(srvloc_tree, hf_srvloc_attrreq_slpspilen, tvb, offset, 2, length);
            offset += 2;
            if (length) {
                proto_tree_add_item(srvloc_tree, hf_srvloc_attrreq_slpspi, tvb, offset, length, ENC_ASCII|ENC_NA);
                offset += length;
            }
            break;

        case ATTRRPLY: /* RFC2608 10.4 */
            expert_item = proto_tree_add_item(srvloc_tree, hf_srvloc_error_v2, tvb, offset, 2, ENC_BIG_ENDIAN);
            expert_status = tvb_get_ntohs(tvb, offset);
            if (expert_status!=0) {
                expert_add_info_format(pinfo, expert_item, PI_RESPONSE_CODE, PI_ERROR, "Error: %s", val_to_str(expert_status, srvloc_errs_v2, "Unknown SRVLOC Error (0x%02x)"));
            }
            offset += 2;
            length = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint(srvloc_tree, hf_srvloc_attrrply_attrlistlen, tvb, offset, 2, length);
            offset += 2;
            if (length) {
                attr_list2(srvloc_tree, hf_srvloc_attrrply_attrlist, tvb, offset, length, CHARSET_UTF_8);
                offset += length;
            }
            count = tvb_get_guint8(tvb, offset);
            proto_tree_add_uint(srvloc_tree, hf_srvloc_attrrply_attrauthcount, tvb, offset, 1, count);
            offset += 1;
            while (count > 0) {
                offset = dissect_attrauthblk_v2(tvb, offset, srvloc_tree);
                count--;
            }
            break;

        case DAADVERT: /* RCC 2608 8.5 */
            expert_item = proto_tree_add_item(srvloc_tree, hf_srvloc_error_v2, tvb, offset, 2, ENC_BIG_ENDIAN);
            expert_status = tvb_get_ntohs(tvb, offset);
            if (expert_status!=0) {
                expert_add_info_format(pinfo, expert_item, PI_RESPONSE_CODE, PI_ERROR, "Error: %s", val_to_str(expert_status, srvloc_errs_v2, "Unknown SRVLOC Error (0x%02x)"));
            }
            offset += 2;
            ts.nsecs = 0;
            ts.secs = tvb_get_ntohl(tvb, offset);
            proto_tree_add_time(srvloc_tree, hf_srvloc_daadvert_timestamp, tvb, offset, 4,
                                &ts);
            offset += 4;
            length = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint(srvloc_tree, hf_srvloc_daadvert_urllen, tvb, offset, 2, length);
            offset += 2;
            if (length) {
                proto_tree_add_item(srvloc_tree, hf_srvloc_daadvert_url, tvb, offset, length, ENC_ASCII|ENC_NA);
                offset += length;
            }
            length = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint(srvloc_tree, hf_srvloc_daadvert_scopelistlen, tvb, offset, 2, length);
            offset += 2;
            if (length) {
                proto_tree_add_item(srvloc_tree, hf_srvloc_daadvert_scopelist, tvb, offset, length, ENC_ASCII|ENC_NA);
                offset += length;
            }
            length = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint(srvloc_tree, hf_srvloc_daadvert_attrlistlen, tvb, offset, 2, length);
            offset += 2;
            if (length) {
                proto_tree_add_item(srvloc_tree, hf_srvloc_daadvert_attrlist, tvb, offset, length, ENC_ASCII|ENC_NA);
                offset += length;
            }
            length = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint(srvloc_tree, hf_srvloc_daadvert_slpspilen, tvb, offset, 2, length);
            offset += 2;
            if (length) {
                proto_tree_add_item(srvloc_tree, hf_srvloc_daadvert_slpspi, tvb, offset, length, ENC_ASCII|ENC_NA);
                offset += length;
            }
            count = tvb_get_guint8(tvb, offset);
            proto_tree_add_uint(srvloc_tree, hf_srvloc_daadvert_authcount, tvb, offset, 1, count);
            offset += 1;
            while (count > 0) {
                offset = dissect_authblk_v2(tvb, offset, srvloc_tree);
                count--;
            }
            break;

        case SRVTYPERQST: /* RFC2608 10.1 */
            length = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint(srvloc_tree, hf_srvloc_srvtypereq_prlistlen, tvb, offset, 2, length);
            offset += 2;
            if (length) {
                proto_tree_add_item(srvloc_tree, hf_srvloc_srvtypereq_prlist, tvb, offset, length, ENC_ASCII|ENC_NA);
                offset += length;
            }
            length = tvb_get_ntohs(tvb, offset);
            if (0xFFFF == length) {
                proto_tree_add_uint(srvloc_tree, hf_srvloc_srvtypereq_nameauthlistlenall, tvb, offset, 2, length);
                offset += 2;
            } else {
                proto_tree_add_uint(srvloc_tree, hf_srvloc_srvtypereq_nameauthlistlen, tvb, offset, 2, length);
                offset += 2;
                if (length) {
                    proto_tree_add_item(srvloc_tree, hf_srvloc_srvtypereq_nameauthlist, tvb, offset, length, ENC_ASCII|ENC_NA);
                    offset += length;
                }
            }
            length = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint(srvloc_tree, hf_srvloc_srvtypereq_scopelistlen, tvb, offset, 2, length);
            offset += 2;
            if (length) {
                proto_tree_add_item(srvloc_tree, hf_srvloc_srvtypereq_scopelist, tvb, offset, length, ENC_ASCII|ENC_NA);
                offset += length;
            }
            break;

        case SRVTYPERPLY: /* rfc2608 10.2 */
            expert_item = proto_tree_add_item(srvloc_tree, hf_srvloc_error_v2, tvb, offset, 2, ENC_BIG_ENDIAN);
            expert_status = tvb_get_ntohs(tvb, offset);
            if (expert_status!=0) {
                expert_add_info_format(pinfo, expert_item, PI_RESPONSE_CODE, PI_ERROR, "Error: %s", val_to_str(expert_status, srvloc_errs_v2, "Unknown SRVLOC Error (0x%02x)"));
            }
            offset += 2;
            length = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint(srvloc_tree, hf_srvloc_srvtyperply_srvtypelistlen, tvb, offset, 2, length);
            offset += 2;
            if (length) {
                proto_tree_add_item(srvloc_tree, hf_srvloc_srvtyperply_srvtypelist, tvb, offset, length, ENC_ASCII|ENC_NA);
                offset += length;
            }
            break;

        case SAADVERT: /* rfc2608 10.2 */
            length = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint(srvloc_tree, hf_srvloc_saadvert_urllen, tvb, offset, 2, length);
            offset += 2;
            if (length) {
                proto_tree_add_item(srvloc_tree, hf_srvloc_saadvert_url, tvb, offset, length, ENC_ASCII|ENC_NA);
                offset += length;
            }
            length = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint(srvloc_tree, hf_srvloc_saadvert_scopelistlen, tvb, offset, 2, length);
            offset += 2;
            if (length) {
                proto_tree_add_item(srvloc_tree, hf_srvloc_saadvert_scopelist, tvb, offset, length, ENC_ASCII|ENC_NA);
                offset += length;
            }
            length = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint(srvloc_tree, hf_srvloc_saadvert_attrlistlen, tvb, offset, 2, length);
            offset += 2;
            if (length) {
                proto_tree_add_item(srvloc_tree, hf_srvloc_saadvert_attrlist, tvb, offset, length, ENC_ASCII|ENC_NA);
                offset += length;
            }
            count = tvb_get_guint8(tvb, offset);
            proto_tree_add_uint(srvloc_tree, hf_srvloc_saadvert_authcount, tvb, offset, 1, length);
            offset += 1;
            while (count > 0) {
                offset = dissect_authblk_v2(tvb, offset, srvloc_tree);
                count--;
            }
            break;

        default:
            expert_item = proto_tree_add_text(srvloc_tree, tvb, offset, -1, "Unknown Function Type");
            expert_add_info_format(pinfo, expert_item, PI_RESPONSE_CODE, PI_ERROR, "Unknown Function Type: %d", function);
        }
    }
}

static guint
get_srvloc_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
    /*
     * Get the length of the SRVLOC packet.
     * It starts at offset+2, but it's 2 bytes in SLPv1 and 3 bytes
     * in SLPv2.
     */
    if (tvb_get_guint8(tvb, offset) == 2)
        return tvb_get_ntoh24(tvb, offset + 2);
    else
        return tvb_get_ntohs(tvb, offset + 2);
}

static void
dissect_srvloc_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree	    *srvloc_tree = NULL;
    proto_item	    *ti;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SRVLOC");

    col_clear(pinfo->cinfo, COL_INFO);

    if (tree) {
        ti = proto_tree_add_item(tree, proto_srvloc, tvb, 0, -1, FALSE);
        srvloc_tree = proto_item_add_subtree(ti, ett_srvloc);
    }
    dissect_srvloc(tvb, pinfo, srvloc_tree);
}

static void
dissect_srvloc_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    /*
     * XXX - in SLPv1, the fixed length need only be 4, as the length
     * is 2 bytes long; however, it must be 5 for SLPv2, as the length
     * is 3 bytes long, and there's probably no harm in asking for 5
     * bytes, as even SLPv1 packets start with a 12-byte header,
     * and if the packet has a length that's 4 or less, it's bogus,
     * and we can't handle a length < 4 anyway.
     */
    tcp_dissect_pdus(tvb, pinfo, tree, srvloc_desegment, 5, get_srvloc_pdu_len,
	dissect_srvloc_pdu);
}

/* Register protocol with Wireshark. */

void
proto_register_srvloc(void)
{
    static hf_register_info hf[] = {
	/* Helper functions for the Version 1 Header*/
        {&hf_srvloc_error,
            {"Error Code", "srvloc.err",
            FT_UINT16, BASE_DEC, VALS(srvloc_errs), 0x0,
            NULL, HFILL }
        },

	/* Helper function for the Version 2 Header */
        {&hf_srvloc_error_v2,
            {"Error Code", "srvloc.errv2",
            FT_UINT16, BASE_DEC, VALS(srvloc_errs_v2), 0x0,
            NULL, HFILL }
        },
        {&hf_srvloc_xid,
            {"XID", "srvloc.xid",
            FT_UINT24, BASE_DEC, NULL, 0x0,
            "Transaction ID", HFILL }
        },
        {&hf_srvloc_langtag,
            {"Lang Tag", "srvloc.langtag",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        {&hf_srvloc_langtaglen,
            {"Lang Tag Len", "srvloc.langtaglen",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        {&hf_srvloc_nextextoff,
            {"Next Extension Offset", "srvloc.nextextoff",
            FT_UINT24, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

	/* Helper functions for URL and URL Entry parsing - both versions */
	{&hf_srvloc_url_reserved,
	 {"Reserved", "srvloc.url.reserved",
	  FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
	},
	{&hf_srvloc_url_lifetime,
	 {"URL lifetime", "srvloc.url.lifetime",
	  FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
	},
	{&hf_srvloc_url_urllen,
	 {"URL Length", "srvloc.url.urllen",
	  FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
	},
	{&hf_srvloc_url_url,
	 {"URL", "srvloc.url.url",
	  FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
	},
	{&hf_srvloc_url_numauths,
	 {"Num Auths", "srvloc.url.numauths",
	  FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
	},

	/* Helper functions for the common header fields */
        {&hf_srvloc_function,
            {"Function", "srvloc.function",
            FT_UINT8, BASE_DEC, VALS(srvloc_functions), 0x0,
            NULL, HFILL }
        },

        {&hf_srvloc_pktlen,
            {"Packet Length", "srvloc.pktlen",
            FT_UINT24, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_srvloc_version,
            { "Version",           "srvloc.version",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        {&hf_srvloc_flags_v1,
            {"Flags", "srvloc.flags_v1",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },

	{ &hf_srvloc_flags_v1_overflow,
	  { "Overflow", "srvloc.flags_v1.overflow.", FT_BOOLEAN, 8,
	    TFS(&tfs_srvloc_flags_overflow), FLAG_O, "Can whole packet fit into a datagram?", HFILL }},

	{ &hf_srvloc_flags_v1_monolingual,
	  { "Monolingual", "srvloc.flags_v1.monolingual", FT_BOOLEAN, 8,
	    TFS(&tfs_srvloc_flags_v1_monolingual), FLAG_M, "Can whole packet fit into a datagram?", HFILL }},

	{ &hf_srvloc_flags_v1_url_auth,
	  { "URL Authentication", "srvloc.flags_v1.url_auth", FT_BOOLEAN, 8,
	    TFS(&tfs_srvloc_flags_v1_url_auth), FLAG_U, "Can whole packet fit into a datagram?", HFILL }},

	{ &hf_srvloc_flags_v1_attribute_auth,
	  { "Attribute Authentication", "srvloc.flags_v1.attribute_auth", FT_BOOLEAN, 8,
	    TFS(&tfs_srvloc_flags_v1_attribute_auth), FLAG_A, "Can whole packet fit into a datagram?", HFILL }},

	{ &hf_srvloc_flags_v1_fresh,
	  { "Fresh Registration", "srvloc.flags_v1.fresh", FT_BOOLEAN, 8,
	    TFS(&tfs_srvloc_flags_fresh), FLAG_F, "Is this a new registration?", HFILL }},

        {&hf_srvloc_flags_v2,
            {"Flags", "srvloc.flags_v2",
            FT_UINT16, BASE_HEX, NULL, 0x0,
             NULL, HFILL }
         },

	{ &hf_srvloc_flags_v2_overflow,
	  { "Overflow", "srvloc.flags_v2.overflow", FT_BOOLEAN, 16,
	    TFS(&tfs_srvloc_flags_overflow), FLAG_O_V2, "Can whole packet fit into a datagram?", HFILL }},

	{ &hf_srvloc_flags_v2_fresh,
	  { "Fresh Registration", "srvloc.flags_v2.fresh", FT_BOOLEAN, 16,
	    TFS(&tfs_srvloc_flags_fresh), FLAG_F_V2, "Is this a new registration?", HFILL }},

	{ &hf_srvloc_flags_v2_reqmulti,
	  { "Multicast requested", "srvloc.flags_v2.reqmulti", FT_BOOLEAN, 16,
	    TFS(&tfs_srvloc_flags_v2_reqmulti), FLAG_R_V2, "Do we want multicast?", HFILL }},

	/* collection of helper functions for dissect_authblk_v2 */
	{ &hf_srvloc_authblkv2_bsd,
	  { "BSD", "srvloc.authblkv2_bsd", FT_UINT16, BASE_HEX, NULL, 0x0,
	    "Block Structure Descriptor", HFILL}
	},
	{ &hf_srvloc_authblkv2_len,
	  { "Length", "srvloc.authblkv2_len", FT_UINT16, BASE_DEC, NULL, 0x0,
	    "Length of Authentication Block", HFILL}
	},
	{ &hf_srvloc_authblkv2_timestamp,
	  { "Timestamp", "srvloc.authblkv2.timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
	    NULL, 0, "Timestamp on Authentication Block", HFILL }
	},
	{ &hf_srvloc_authblkv2_slpspilen,
	  { "SLP SPI Length", "srvloc.authblkv2.slpspilen", FT_UINT16, BASE_DEC, NULL, 0x0,
	    "Length of the SLP SPI", HFILL}
	},
	{ &hf_srvloc_authblkv2_slpspi,
	  { "SLP SPI", "srvloc.authblkv2.slpspi", FT_STRING, BASE_NONE, NULL, 0x0,
	    NULL, HFILL}
	},

	/* collection of helper functions for Service Request */
	{ &hf_srvloc_srvreq_prlistlen,
	  { "Previous Response List Length", "srvloc.srvreq.prlistlen", FT_UINT16, BASE_DEC, NULL, 0x0,
	    "Length of Previous Response List", HFILL}
	},
	{ &hf_srvloc_srvreq_prlist,
	  { "Previous Response List", "srvloc.srvreq.prlist", FT_STRING, BASE_NONE, NULL, 0x0,
	    NULL, HFILL}
	},
	{ &hf_srvloc_srvreq_srvtypelen,
	  { "Service Type Length", "srvloc.srvreq.srvtypelen", FT_UINT16, BASE_DEC, NULL, 0x0,
	    "Length of Service Type List", HFILL}
	},
	{ &hf_srvloc_srvreq_srvtypelist,
	  { "Service Type List", "srvloc.srvreq.srvtypelist", FT_STRING, BASE_NONE, NULL, 0x0,
	    NULL, HFILL}
	},
	{ &hf_srvloc_srvreq_scopelistlen,
	  { "Scope List Length", "srvloc.srvreq.scopelistlen", FT_UINT16, BASE_DEC, NULL, 0x0,
	    "Length of the Scope List", HFILL}
	},
	{ &hf_srvloc_srvreq_scopelist,
	  { "Scope List", "srvloc.srvreq.scopelist", FT_STRING, BASE_NONE, NULL, 0x0,
	    NULL, HFILL}
	},
	{ &hf_srvloc_srvreq_predicatelen,
	  { "Predicate Length", "srvloc.srvreq.predicatelen", FT_UINT16, BASE_DEC, NULL, 0x0,
	    "Length of the Predicate", HFILL}
	},
	{ &hf_srvloc_srvreq_predicate,
	  { "Predicate", "srvloc.srvreq.predicate", FT_STRING, BASE_NONE, NULL, 0x0,
	    NULL, HFILL}
	},
	{ &hf_srvloc_srvreq_slpspilen,
	  { "SLP SPI Length", "srvloc.srvreq.slpspilen", FT_UINT16, BASE_DEC, NULL, 0x0,
	    "Length of the SLP SPI", HFILL}
	},
	{ &hf_srvloc_srvreq_slpspi,
	  { "SLP SPI", "srvloc.srvreq.slpspi", FT_STRING, BASE_NONE, NULL, 0x0,
	    NULL, HFILL}
	},

	/* Helper function for Service Request */
	{ &hf_srvloc_srvrply_urlcount,
	  { "Number of URLs", "srvloc.srvreq.urlcount", FT_UINT16, BASE_DEC, NULL, 0x0,
	    NULL, HFILL}
	},

	/* Helper functions for Service Registration */
	{ &hf_srvloc_srvreg_srvtypelen,
	  { "Service Type Length", "srvloc.srvreq.srvtypelen", FT_UINT16, BASE_DEC, NULL, 0x0,
	    NULL, HFILL}
	},
	{ &hf_srvloc_srvreg_srvtype,
	  { "Service Type", "srvloc.srvreq.srvtype", FT_STRING, BASE_NONE, NULL, 0x0,
	    NULL, HFILL}
	},
	{ &hf_srvloc_srvreg_scopelistlen,
	  { "Scope List Length", "srvloc.srvreq.scopelistlen", FT_UINT16, BASE_DEC, NULL, 0x0,
	    NULL, HFILL}
	},
	{ &hf_srvloc_srvreg_scopelist,
	  { "Scope List", "srvloc.srvreq.scopelist", FT_STRING, BASE_NONE, NULL, 0x0,
	    NULL, HFILL}
	},
	{ &hf_srvloc_srvreg_attrlistlen,
	  { "Attribute List Length", "srvloc.srvreq.attrlistlen", FT_UINT16, BASE_DEC, NULL, 0x0,
	    NULL, HFILL}
	},
	{ &hf_srvloc_srvreg_attrlist,
	  { "Attribute List", "srvloc.srvreq.attrlist", FT_STRING, BASE_NONE, NULL, 0x0,
	    NULL, HFILL}
	},
	{ &hf_srvloc_srvreg_attrauthcount,
	  { "Attr Auths", "srvloc.srvreq.attrauthcount", FT_UINT8, BASE_DEC, NULL, 0x0,
	    "Number of Attribute Authentication Blocks", HFILL}
	},

	/* Helper functions for Service Deregistration */
	{ &hf_srvloc_srvdereg_scopelistlen,
	  { "Scope List Length", "srvloc.srvdereq.scopelistlen", FT_UINT16, BASE_DEC, NULL, 0x0,
	    NULL, HFILL}
	},
	{ &hf_srvloc_srvdereg_scopelist,
	  { "Scope List", "srvloc.srvdereq.scopelist", FT_STRING, BASE_NONE, NULL, 0x0,
	    NULL, HFILL}
	},
	{ &hf_srvloc_srvdereg_taglistlen,
	  { "Tag List Length", "srvloc.srvdereq.taglistlen", FT_UINT16, BASE_DEC, NULL, 0x0,
	    NULL, HFILL}
	},
	{ &hf_srvloc_srvdereg_taglist,
	  { "Tag List", "srvloc.srvdereq.taglist", FT_STRING, BASE_NONE, NULL, 0x0,
	    NULL, HFILL}
	},


	/* collection of helper functions for Attribute Request */
	{ &hf_srvloc_attrreq_prlistlen,
	  { "Previous Response List Length", "srvloc.attrreq.prlistlen", FT_UINT16, BASE_DEC, NULL, 0x0,
	    "Length of Previous Response List", HFILL}
	},
	{ &hf_srvloc_attrreq_prlist,
	  { "Previous Response List", "srvloc.attrreq.prlist", FT_STRING, BASE_NONE, NULL, 0x0,
	    NULL, HFILL}
	},
	{ &hf_srvloc_attrreq_urllen,
	  { "URL Length", "srvloc.attrreq.urllen", FT_UINT16, BASE_DEC, NULL, 0x0,
	    NULL, HFILL}
	},
	{ &hf_srvloc_attrreq_url,
	  { "Service URL", "srvloc.attrreq.url", FT_STRING, BASE_NONE, NULL, 0x0,
	    "URL of service", HFILL}
	},
	{ &hf_srvloc_attrreq_scopelistlen,
	  { "Scope List Length", "srvloc.attrreq.scopelistlen", FT_UINT16, BASE_DEC, NULL, 0x0,
	    "Length of the Scope List", HFILL}
	},
	{ &hf_srvloc_attrreq_scopelist,
	  { "Scope List", "srvloc.attrreq.scopelist", FT_STRING, BASE_NONE, NULL, 0x0,
	    NULL, HFILL}
	},
	{ &hf_srvloc_attrreq_attrlistlen,
	  { "Attribute List Length", "srvloc.attrreq.attrlistlen", FT_UINT16, BASE_DEC, NULL, 0x0,
	    NULL, HFILL}
	},
	{ &hf_srvloc_attrreq_attrlist,
	  { "Attribute List", "srvloc.attrreq.attrlist", FT_STRING, BASE_NONE, NULL, 0x0,
	    NULL, HFILL}
	},
	{ &hf_srvloc_attrreq_taglistlen,
	  { "Tag List Length", "srvloc.attrreq.taglistlen", FT_UINT16, BASE_DEC, NULL, 0x0,
	    NULL, HFILL}
	},
	{ &hf_srvloc_attrreq_taglist,
	  { "Tag List", "srvloc.attrreq.taglist", FT_STRING, BASE_NONE, NULL, 0x0,
	    NULL, HFILL}
	},
	{ &hf_srvloc_attrreq_slpspilen,
	  { "SLP SPI Length", "srvloc.attrreq.slpspilen", FT_UINT16, BASE_DEC, NULL, 0x0,
	    "Length of the SLP SPI", HFILL}
	},
	{ &hf_srvloc_attrreq_slpspi,
	  { "SLP SPI", "srvloc.attrreq.slpspi", FT_STRING, BASE_NONE, NULL, 0x0,
	    NULL, HFILL}
	},

	/* collection of helper functions for Attribute Reply */
	{ &hf_srvloc_attrrply_attrlistlen,
	  { "Attribute List Length", "srvloc.attrrply.attrlistlen", FT_UINT16, BASE_DEC, NULL, 0x0,
	    "Length of Attribute List", HFILL}
	},
	{ &hf_srvloc_attrrply_attrlist,
	  { "Attribute List", "srvloc.attrrply.attrlist", FT_STRING, BASE_NONE, NULL, 0x0,
	    NULL, HFILL}
	},
	{ &hf_srvloc_attrrply_attrauthcount,
	  { "Attr Auths", "srvloc.srvreq.attrauthcount", FT_UINT8, BASE_DEC, NULL, 0x0,
	    "Number of Attribute Authentication Blocks", HFILL}
	},

	/* collection of helper functions for DA Advertisement */
	{ &hf_srvloc_daadvert_timestamp,
	  { "DAADVERT Timestamp", "srvloc.daadvert.timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
	    NULL, 0, "Timestamp on DA Advert", HFILL }
	},
	{ &hf_srvloc_daadvert_urllen,
	  { "URL Length", "srvloc.daadvert.urllen", FT_UINT16, BASE_DEC, NULL, 0x0,
	    NULL, HFILL}
	},
	{ &hf_srvloc_daadvert_url,
	  { "URL", "srvloc.daadvert.url", FT_STRING, BASE_NONE, NULL, 0x0,
	    NULL, HFILL}
	},
	{ &hf_srvloc_daadvert_scopelistlen,
	  { "Scope List Length", "srvloc.daadvert.scopelistlen", FT_UINT16, BASE_DEC, NULL, 0x0,
	    "Length of the Scope List", HFILL}
	},
	{ &hf_srvloc_daadvert_scopelist,
	  { "Scope List", "srvloc.daadvert.scopelist", FT_STRING, BASE_NONE, NULL, 0x0,
	    NULL, HFILL}
	},
	{ &hf_srvloc_daadvert_attrlistlen,
	  { "Attribute List Length", "srvloc.daadvert.attrlistlen", FT_UINT16, BASE_DEC, NULL, 0x0,
	    NULL, HFILL}
	},
	{ &hf_srvloc_daadvert_attrlist,
	  { "Attribute List", "srvloc.daadvert.attrlist", FT_STRING, BASE_NONE, NULL, 0x0,
	    NULL, HFILL}
	},
	{ &hf_srvloc_daadvert_slpspilen,
	  { "SLP SPI Length", "srvloc.daadvert.slpspilen", FT_UINT16, BASE_DEC, NULL, 0x0,
	    "Length of the SLP SPI", HFILL}
	},
	{ &hf_srvloc_daadvert_slpspi,
	  { "SLP SPI", "srvloc.daadvert.slpspi", FT_STRING, BASE_NONE, NULL, 0x0,
	    NULL, HFILL}
	},
	{ &hf_srvloc_daadvert_authcount,
	  { "Auths", "srvloc.daadvert.authcount", FT_UINT8, BASE_DEC, NULL, 0x0,
	    "Number of Authentication Blocks", HFILL}
	},

	/* collection of helper functions for Service Type Request */
	{ &hf_srvloc_srvtypereq_prlistlen,
	  { "Previous Response List Length", "srvloc.srvtypereq.prlistlen", FT_UINT16, BASE_DEC, NULL, 0x0,
	    "Length of Previous Response List", HFILL}
	},
	{ &hf_srvloc_srvtypereq_prlist,
	  { "Previous Response List", "srvloc.srvtypereq.prlist", FT_STRING, BASE_NONE, NULL, 0x0,
	    NULL, HFILL}
	},
	{ &hf_srvloc_srvtypereq_nameauthlistlen,
	  { "Naming Authority List Length", "srvloc.srvtypereq.nameauthlistlen", FT_UINT16, BASE_DEC, NULL, 0x0,
	    "Length of the Naming Authority List", HFILL}
	},
	{ &hf_srvloc_srvtypereq_nameauthlistlenall,
	  { "Naming Authority List Length (All Naming Authorities)", "srvloc.srvtypereq.nameauthlistlen", FT_UINT16, BASE_DEC, NULL, 0x0,
	    "Length of the Naming Authority List", HFILL}
	},
	{ &hf_srvloc_srvtypereq_nameauthlist,
	  { "Naming Authority List", "srvloc.srvtypereq.nameauthlist", FT_STRING, BASE_NONE, NULL, 0x0,
	    NULL, HFILL}
	},
	{ &hf_srvloc_srvtypereq_scopelistlen,
	  { "Scope List Length", "srvloc.srvtypereq.scopelistlen", FT_UINT16, BASE_DEC, NULL, 0x0,
	    "Length of the Scope List", HFILL}
	},
	{ &hf_srvloc_srvtypereq_scopelist,
	  { "Scope List", "srvloc.srvtypereq.scopelist", FT_STRING, BASE_NONE, NULL, 0x0,
	    NULL, HFILL}
	},

	/* collection of helper functions for Service Type Replies */
	{ &hf_srvloc_srvtyperply_srvtypelen,
	  { "Service Type Length", "srvloc.srvtypereq.srvtypelen", FT_UINT16, BASE_DEC, NULL, 0x0,
	    "Length of the Service Type", HFILL}
	},
	{ &hf_srvloc_srvtyperply_srvtype,
	  { "Service Type", "srvloc.srvtyperply.srvtype", FT_STRING, BASE_NONE, NULL, 0x0,
	    NULL, HFILL}
	},
	{ &hf_srvloc_srvtyperply_srvtypelistlen,
	  { "Service Type List Length", "srvloc.srvtypereq.srvtypelistlen", FT_UINT16, BASE_DEC, NULL, 0x0,
	    "Length of the Service Type List", HFILL}
	},
	{ &hf_srvloc_srvtyperply_srvtypelist,
	  { "Service Type List", "srvloc.srvtyperply.srvtypelist", FT_STRING, BASE_NONE, NULL, 0x0,
	    NULL, HFILL}
	},

	/* collection of helper functions for SA Advertisement */
	{ &hf_srvloc_saadvert_urllen,
	  { "URL Length", "srvloc.saadvert.urllen", FT_UINT16, BASE_DEC, NULL, 0x0,
	    NULL, HFILL}
	},
	{ &hf_srvloc_saadvert_url,
	  { "URL", "srvloc.saadvert.url", FT_STRING, BASE_NONE, NULL, 0x0,
	    NULL, HFILL}
	},
	{ &hf_srvloc_saadvert_scopelistlen,
	  { "Scope List Length", "srvloc.saadvert.scopelistlen", FT_UINT16, BASE_DEC, NULL, 0x0,
	    "Length of the Scope List", HFILL}
	},
	{ &hf_srvloc_saadvert_scopelist,
	  { "Scope List", "srvloc.saadvert.scopelist", FT_STRING, BASE_NONE, NULL, 0x0,
	    NULL, HFILL}
	},
	{ &hf_srvloc_saadvert_attrlistlen,
	  { "Attribute List Length", "srvloc.saadvert.attrlistlen", FT_UINT16, BASE_DEC, NULL, 0x0,
	    NULL, HFILL}
	},
	{ &hf_srvloc_saadvert_attrlist,
	  { "Attribute List", "srvloc.saadvert.attrlist", FT_STRING, BASE_NONE, NULL, 0x0,
	    NULL, HFILL}
	},
	{ &hf_srvloc_saadvert_authcount,
	  { "Auths", "srvloc.saadvert.authcount", FT_UINT8, BASE_DEC, NULL, 0x0,
	    "Number of Authentication Blocks", HFILL}
	},
	{ &hf_srvloc_add_ref_ip,
	  { "IP Address", "srvloc.list.ipaddr", FT_IPv4, BASE_NONE, NULL, 0x0,
	    "IP Address of SLP server", HFILL}
	},
	{ &hf_srvloc_srvrply_svcname,
	  { "Service Name Value", "srvloc.srvrply.svcname", FT_STRING, BASE_NONE, NULL, 0x0,
	    NULL, HFILL}
	}
    };

    static gint *ett[] = {
	&ett_srvloc,
	&ett_srvloc_attr,
	&ett_srvloc_flags,
    };
	module_t *srvloc_module;

    proto_srvloc = proto_register_protocol("Service Location Protocol",
					   "SRVLOC", "srvloc");
    proto_register_field_array(proto_srvloc, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
	srvloc_module = prefs_register_protocol(proto_srvloc, NULL);
	prefs_register_bool_preference(srvloc_module, "desegment_tcp",
	    "Reassemble SRVLOC messages spanning multiple TCP segments",
	    "Whether the SRVLOC dissector should reassemble messages spanning multiple TCP segments. "
	    "To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
	    &srvloc_desegment);
}

void
proto_reg_handoff_srvloc(void)
{
    dissector_handle_t srvloc_handle, srvloc_tcp_handle;
    srvloc_handle = create_dissector_handle(dissect_srvloc, proto_srvloc);
    dissector_add_uint("udp.port", UDP_PORT_SRVLOC, srvloc_handle);
    srvloc_tcp_handle = create_dissector_handle(dissect_srvloc_tcp,
						proto_srvloc);
    dissector_add_uint("tcp.port", TCP_PORT_SRVLOC, srvloc_tcp_handle);
}
