/* packet-srvloc.c
 * Routines for SRVLOC (Service Location Protocol) packet dissection
 * Copyright 1999, James Coe <jammer@cin.net>
 *
 * NOTE: This is Alpha software not all features have been verified yet.
 *       In particular I have not had an opportunity to see how it 
 *       responds to SRVLOC over TCP.
 *
 * $Id: packet-srvloc.c,v 1.28 2002/01/21 07:36:43 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 *
 * Service Location Protocol is RFC 2165
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

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <string.h>
#include <time.h>
#include <glib.h>

#ifdef NEED_SNPRINTF_H
# include "snprintf.h"
#endif

#include <epan/packet.h>
#include <epan/strutil.h>

static int proto_srvloc = -1;
static int hf_srvloc_version = -1;
static int hf_srvloc_function = -1;
static int hf_srvloc_flags = -1;
static int hf_srvloc_error = -1;

static gint ett_srvloc = -1;
static gint ett_srvloc_flags = -1;

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

/* Create protocol header structure */

struct srvloc_hdr {
    guint8	version;
    guint8	function;
    guint16	length;
    guint8	flags;
    guint8	dialect;
    u_char	language[2];
    guint16	encoding;
    guint16	xid;
};

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
    { 0, NULL }
};

/* List to resolve flag values to names */


/* Define flag masks */

#define FLAG_O		0x80
#define FLAG_M		0x40
#define FLAG_U		0x20
#define FLAG_A		0x10
#define FLAG_F		0x08

/* Define Error Codes */

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

/*
 * Character encodings.
 * This is a small subset of what's in
 *
 *	http://www.isi.edu/in-notes/iana/assignments/character-sets
 *
 * XXX - we should do something useful with this, i.e. properly
 * handle strings based on the character set they're in.
 *
 * XXX - what does "properly handle strings" mean?  How do we know
 * what character set the terminal can handle (for tty-based code)
 * or the GUI can handle (for GUI code)?
 *
 * XXX - the Ethereal core really should be what does all the
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
    struct tm *stamp;
    time_t seconds;
    double floatsec;
    guint16 length;
    
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
    proto_tree_add_text(tree, tvb, offset + 8, 2, "Block Structure Desciptor: %u",
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

/* Packet dissection routine called by tcp & udp when port 427 detected */

static void
dissect_srvloc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int offset = 0;
    proto_item *ti, *tf;
    proto_tree *srvloc_tree, *srvloc_flags;
    guint8 version;
    guint8 function;
    guint16 encoding;
    guint16 length;
    guint8 flags;
    guint32 count;

    if (check_col(pinfo->cinfo, COL_PROTOCOL))
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "SRVLOC");
    
    if (check_col(pinfo->cinfo, COL_INFO))
        col_clear(pinfo->cinfo, COL_INFO);

    version = tvb_get_guint8(tvb, offset);
    function = tvb_get_guint8(tvb, offset + 1);

    if (check_col(pinfo->cinfo, COL_INFO))
        col_add_str(pinfo->cinfo, COL_INFO,
            val_to_str(function, srvloc_functions, "Unknown Function (%u)"));
        
    if (tree) {
        ti = proto_tree_add_item(tree, proto_srvloc, tvb, offset,
                                 tvb_length(tvb), FALSE);
        srvloc_tree = proto_item_add_subtree(ti, ett_srvloc);
    
        proto_tree_add_uint(srvloc_tree, hf_srvloc_version, tvb, offset, 1,
                            version);
        proto_tree_add_uint(srvloc_tree, hf_srvloc_function, tvb, offset + 1, 1,
                            function);
        length = tvb_get_ntohs(tvb, offset + 2);
        proto_tree_add_text(srvloc_tree, tvb, offset + 2, 2, "Length: %u",
                            length);
        flags = tvb_get_guint8(tvb, offset + 4);
        tf = proto_tree_add_uint(srvloc_tree, hf_srvloc_flags, tvb, offset + 4, 1,
                                 flags);
        srvloc_flags = proto_item_add_subtree(tf, ett_srvloc_flags);
        proto_tree_add_text(srvloc_flags, tvb, offset + 4, 0, "Overflow                          %d... .xxx", (flags & FLAG_O) >> 7 );
        proto_tree_add_text(srvloc_flags, tvb, offset + 4, 0, "Monolingual                       .%d.. .xxx", (flags & FLAG_M) >> 6 );
        proto_tree_add_text(srvloc_flags, tvb, offset + 4, 0, "URL Authentication Present        ..%d. .xxx", (flags & FLAG_U) >> 5 );
        proto_tree_add_text(srvloc_flags, tvb, offset + 4, 0, "Attribute Authentication Present  ...%d .xxx", (flags & FLAG_A) >> 4 );
        proto_tree_add_text(srvloc_flags, tvb, offset + 4, 0, "Fresh Service Entry               .... %dxxx", (flags & FLAG_F) >> 3 );
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
        offset += 12;
        
        switch (function) {
            case SRVREQ:
                proto_tree_add_text(srvloc_tree, tvb, offset, 0, "Service Request");
                length = tvb_get_ntohs(tvb, offset);
                proto_tree_add_text(srvloc_tree, tvb, offset, 2, "Previous Response List Length: %u",
                                    length);
                offset += 2;
                proto_tree_add_text(srvloc_tree, tvb, offset, length, "Previous Response List: %s",
                                    tvb_format_text(tvb, offset, length));
                offset += length;
                length = tvb_get_ntohs(tvb, offset);
                proto_tree_add_text(srvloc_tree, tvb, offset, 2, "Predicate length: %u",
                                    length);
                offset += 2;
                proto_tree_add_text(srvloc_tree, tvb, offset, length, "Predicate: %s",
                                    tvb_format_text(tvb, offset, length));
                offset += length;
            break;
            
            case SRVRPLY:
                proto_tree_add_text(srvloc_tree, tvb, offset, 0, "Service Reply");
                proto_tree_add_item(srvloc_tree, hf_srvloc_error, tvb, offset, 2, FALSE);
                offset += 2;
                count = tvb_get_ntohs(tvb, offset);
                proto_tree_add_text(srvloc_tree, tvb, offset, 2, "URL Count: %u",
                                    count);
                offset += 2;
                while (count > 0) {
                    proto_tree_add_text(srvloc_tree, tvb, offset, 2, "URL lifetime: %u",
                                        tvb_get_ntohs(tvb, offset));
                    offset += 2;
                    length = tvb_get_ntohs(tvb, offset);
                    proto_tree_add_text(srvloc_tree, tvb, offset, 2, "URL length: %u",
                                        length);
                    offset += 2;
                    proto_tree_add_text(srvloc_tree, tvb, offset, length, "Service URL: %s",
                                        tvb_format_text(tvb, offset, length));
                    offset += length;
                    if ( (flags & FLAG_U) == FLAG_U ) 
                        offset = dissect_authblk(tvb, offset, srvloc_tree);
                    count--;
                };
            break;

            case SRVREG:
                proto_tree_add_text(srvloc_tree, tvb, offset, 0, "Service Registration");
                proto_tree_add_text(srvloc_tree, tvb, offset, 2, "URL lifetime: %u",
                                    tvb_get_ntohs(tvb, offset));
                offset += 2;
                length = tvb_get_ntohs(tvb, offset);
                proto_tree_add_text(srvloc_tree, tvb, offset, 2, "URL length: %u",
                                    length);
                offset += 2;
                proto_tree_add_text(srvloc_tree, tvb, offset, length, "Service URL: %s",
                                    tvb_format_text(tvb, offset, length));
                offset += length;
                if ( (flags & FLAG_U) == FLAG_U ) 
                    offset = dissect_authblk(tvb, offset, srvloc_tree);
                length = tvb_get_ntohs(tvb, offset);
                proto_tree_add_text(srvloc_tree, tvb, offset, 2, "Attribute List length: %u",
                                    length);
                offset += 2;
                proto_tree_add_text(srvloc_tree, tvb, offset, length, "Attribute List: %s",
                                    tvb_format_text(tvb, offset, length));
                offset += length;
                if ( (flags & FLAG_A) == FLAG_A ) 
                    offset = dissect_authblk(tvb, offset, srvloc_tree);
            break;

            case SRVDEREG:
                proto_tree_add_text(srvloc_tree, tvb, offset, 0, "Service Deregister");
                length = tvb_get_ntohs(tvb, offset);
                proto_tree_add_text(srvloc_tree, tvb, offset, 2, "URL length: %u",
                                    length);
                offset += 2;
                proto_tree_add_text(srvloc_tree, tvb, offset, length, "Service URL: %s",
                                    tvb_format_text(tvb, offset, length));
                offset += length;
                if ( (flags & FLAG_U) == FLAG_U ) 
                    offset = dissect_authblk(tvb, offset, srvloc_tree);
                length = tvb_get_ntohs(tvb, offset);
                proto_tree_add_text(srvloc_tree, tvb, offset, 2, "Attribute List length: %u",
                                    length);
                offset += 2;
                proto_tree_add_text(srvloc_tree, tvb, offset, length, "Attribute List: %s",
                                    tvb_format_text(tvb, offset, length));
                offset += length;
                if ( (flags & FLAG_A) == FLAG_A ) 
                    offset = dissect_authblk(tvb, offset, srvloc_tree);
            break;
            
            case SRVACK:
                proto_tree_add_text(srvloc_tree, tvb, offset, 0, "Service Acknowledge");
                proto_tree_add_item(srvloc_tree, hf_srvloc_error, tvb, offset, 2, FALSE);
                offset += 2;
            break;

            case ATTRRQST:
                proto_tree_add_text(srvloc_tree, tvb, offset, 0, "Attribute Request");
                length = tvb_get_ntohs(tvb, offset);
                proto_tree_add_text(srvloc_tree, tvb, offset, 2, "Previous Response List Length: %u",
                                    length);
                offset += 2;
                proto_tree_add_text(srvloc_tree, tvb, offset, length, "Previous Response List: %s",
                                    tvb_format_text(tvb, offset, length));
                offset += length;
                length = tvb_get_ntohs(tvb, offset);
                proto_tree_add_text(srvloc_tree, tvb, offset, 2, "URL length: %u",
                                    length);
                offset += 2;
                proto_tree_add_text(srvloc_tree, tvb, offset, length, "Service URL: %s",
                                    tvb_format_text(tvb, offset, length));
                offset += length;
                length = tvb_get_ntohs(tvb, offset);
                proto_tree_add_text(srvloc_tree, tvb, offset, 2, "Scope List Length: %u",
                                    length);
                offset += 2;
                proto_tree_add_text(srvloc_tree, tvb, offset, length, "Scope Response List: %s",
                                    tvb_format_text(tvb, offset, length));
                offset += length;
                length = tvb_get_ntohs(tvb, offset);
                proto_tree_add_text(srvloc_tree, tvb, offset, 2, "Attribute List length: %u",
                                    length);
                offset += 2;
                proto_tree_add_text(srvloc_tree, tvb, offset, length, "Attribute List: %s",
                                    tvb_format_text(tvb, offset, length));
                offset += length;
            break;
            
            case ATTRRPLY:
                proto_tree_add_text(srvloc_tree, tvb, offset, 0, "Attribute Reply");
                proto_tree_add_item(srvloc_tree, hf_srvloc_error, tvb, offset, 2, FALSE);
                offset += 2;
                length = tvb_get_ntohs(tvb, offset);
                proto_tree_add_text(srvloc_tree, tvb, offset, 2, "Attribute List length: %u",
                                    length);
                offset += 2;
                proto_tree_add_text(srvloc_tree, tvb, offset, length, "Attribute List: %s",
                                    tvb_format_text(tvb, offset, length));
                offset += length;
                if ( (flags & FLAG_A) == FLAG_A ) 
                    offset = dissect_authblk(tvb, offset, srvloc_tree);
            break;
            
            case DAADVERT:
                proto_tree_add_text(srvloc_tree, tvb, offset, 0, "DA Advertisement");
                proto_tree_add_item(srvloc_tree, hf_srvloc_error, tvb, offset, 2, FALSE);
                offset += 2;
                length = tvb_get_ntohs(tvb, offset);
                proto_tree_add_text(srvloc_tree, tvb, offset, 2, "URL length: %u",
                                    length);
                offset += 2;
                proto_tree_add_text(srvloc_tree, tvb, offset, length, "Service URL: %s",
                                    tvb_format_text(tvb, offset, length));
                offset += length;
                length = tvb_get_ntohs(tvb, offset);
                proto_tree_add_text(srvloc_tree, tvb, offset, 2, "Scope List Length: %u",
                                    length);
                offset += 2;
                proto_tree_add_text(srvloc_tree, tvb, offset, length, "Scope Response List: %s",
                                    tvb_format_text(tvb, offset, length));
                offset += length;
            break;

            case SRVTYPERQST:
                proto_tree_add_text(srvloc_tree, tvb, offset, 0, "Service Type Request");
                length = tvb_get_ntohs(tvb, offset);
                proto_tree_add_text(srvloc_tree, tvb, offset, 2, "Previous Response List Length: %u",
                                    length);
                offset += 2;
                proto_tree_add_text(srvloc_tree, tvb, offset, length, "Previous Response List: %s",
                                    tvb_format_text(tvb, offset, length));
                offset += length;
                length = tvb_get_ntohs(tvb, offset);
                proto_tree_add_text(srvloc_tree, tvb, offset, 2, "Naming Authority List length: %u",
                                    length);
                offset += 2;
                proto_tree_add_text(srvloc_tree, tvb, offset, length, "Naming Authority List: %s",
                                    tvb_format_text(tvb, offset, length));
                offset += length;
                length = tvb_get_ntohs(tvb, offset);
                proto_tree_add_text(srvloc_tree, tvb, offset, 2, "Scope List Length: %u",
                                    length);
                offset += 2;
                proto_tree_add_text(srvloc_tree, tvb, offset, length, "Scope Response List: %s",
                                    tvb_format_text(tvb, offset, length));
                offset += length;
            break;

            case SRVTYPERPLY:
                proto_tree_add_text(srvloc_tree, tvb, offset, 0, "Service Type Reply");
                proto_tree_add_item(srvloc_tree, hf_srvloc_error, tvb, offset, 2, FALSE);
                offset += 2;
                count = tvb_get_ntohs(tvb, offset);
                proto_tree_add_text(srvloc_tree, tvb, offset, 2, "Service Type Count: %u",
                                    count);
                offset += 2;
                while (count > 0) {
                    length = tvb_get_ntohs(tvb, offset);
                    proto_tree_add_text(srvloc_tree, tvb, offset, 2, "Service Type List length: %u",
                                        length);
                    offset += 2;
                    proto_tree_add_text(srvloc_tree, tvb, offset, length, "Service Type List: %s",
                                        tvb_format_text(tvb, offset, length));
                    offset += length;
                    count--;
                };
            break;

            default:
                proto_tree_add_text(srvloc_tree, tvb, offset, tvb_length_remaining(tvb, offset), "Unknown Function Type");
        };
    };
}

/* Register protocol with Ethereal. */

void
proto_register_srvloc(void)
{
    static hf_register_info hf[] = {
        { &hf_srvloc_version,
            { "Version",           "srvloc.version",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "", HFILL }
        },
      
        {&hf_srvloc_function,
            {"Function", "srvloc.function", 
            FT_UINT8, BASE_DEC, VALS(srvloc_functions), 0x0, 
            "", HFILL }
        },

        {&hf_srvloc_flags,
            {"Flags", "srvloc.flags", 
            FT_UINT8, BASE_HEX, NULL, 0x0, 
            "", HFILL }
        },
        
        {&hf_srvloc_error,
            {"Error Code", "srvloc.err",
            FT_UINT16, BASE_DEC, VALS(srvloc_errs), 0x0,
            "", HFILL }
        },
    };
                  
    static gint *ett[] = {
	&ett_srvloc,
	&ett_srvloc_flags,
    };

    proto_srvloc = proto_register_protocol("Service Location Protocol",
					   "SRVLOC", "srvloc");
    proto_register_field_array(proto_srvloc, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
};

void
proto_reg_handoff_srvloc(void)
{
    dissector_handle_t srvloc_handle;

    srvloc_handle = create_dissector_handle(dissect_srvloc, proto_srvloc);
    dissector_add("tcp.port", TCP_PORT_SRVLOC, srvloc_handle);
    dissector_add("udp.port", UDP_PORT_SRVLOC, srvloc_handle);
}
