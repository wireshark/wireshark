/* packet-wbxml.c
 *
 * Routines for wbxml dissection
 * Copyright 2003, Olivier Biot <olivier.biot (ad) siemens.com>
 *
 * $Id: packet-wbxml.c,v 1.24 2004/02/05 18:57:14 obiot Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 *
 * WAP Binary XML decoding functionality provided by Olivier Biot.
 * 
 * The WAP specifications are found at the WAP Forum:
 * http://www.wapforum.org/what/Technical.htm
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

/* Edit this file with 4-space tabulation */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#ifdef NEED_SNPRINTF_H
# include "snprintf.h"
#endif

#include <epan/packet.h>

/* We need the function tvb_get_guintvar() */
#include "packet-wap.h"

/* General-purpose debug logger.
 * Requires double parentheses because of variable arguments of printf().
 *
 * Enable debug logging for WBXML by defining AM_FLAGS
 * so that it contains "-DDEBUG_wbxml"
 */
#ifdef DEBUG_wbxml
#define DebugLog(x) \
	printf("%s:%u: ", __FILE__, __LINE__); \
	printf x; \
	fflush(stdout)
#else
#define DebugLog(x) ;
#endif

/* The code in this source file dissects the WAP Binary XML content,
 * and if possible renders it. WBXML mappings are defined in the
 * "wbxml_map[]" array.
 *
 * NOTES:
 *
 *  - Code page switches only apply to the following token. In the WBXML/1.x
 *    ABNF notation, it can be proven that the switch_page can only precede
 *    the following tokens:
 *      o  stag      : TAG | LITERAL | LITERAL_A | LITERAL_C | LITERAL_AC
 *      o  attr      : ATTRSTART | ATTRVALUE
 *      o  extension : EXT_I | EXT_T | EXT
 *    Code page switches are displayed in a separate column.
 *
 *  - The WBXML spec states that code pages are static to both the tag and the
 *    attribute state parser. A SWITCH_PAGE within a state switches the code
 *    page of the active state only. Note that code page 255 is reserved for
 *    application-specific (read: testing) purposes.
 *
 *  - In order to render the XML content, recursion is inevitable at some
 *    point (when a tag with content occurs in the content of a tag with
 *    content). The code will however not recurse if this is not strictly
 *    required (e.g., tag without content in the content of a tag with
 *    content).
 *
 *  - I found it useful to display the XML nesting level as a first "column",
 *    followed by the abbreviated WBXML token interpretation. When a mapping
 *    is defined for the parsed WBXML content, then the XML rendering is
 *    displayed with appropriate indentation (maximum nesting level = 255,
 *    after which the nesting and level will safely roll-over to 0).
 *
 *  - The WAP Forum defines the order of precedence for finding out the
 *    WBXML content type (same rules for charset) as follows:
 *      1. Look in the Content-Type WSP header
 *      2. Look in the WBXML header
 *    Currently there is no means of using content type parameters:
 *      o  Type=<some_type>
 *      o  Charset=<charset_of_the_content>
 *    So it is possible some WBXML content types are incorrectly parsed.
 *    This would only be the case when the content type declaration in the
 *    WSP Content-Type header would be different (or would have parameters
 *    which are relevant to the WBXML decoding) from the content type
 *    identifier specified in the WBXML header.
 *    TODO: investigate this and provide correct decoding at all times.
 */

typedef struct _value_valuestring {
  guint32 value;
  const value_string *valstrptr;
} value_valuestring;

/* Tries to match val against each element in the value_value_string array vvs.
 * Returns the associated value_string ptr on a match, or NULL on failure. */
static const value_string *
val_to_valstr(guint32 val, const value_valuestring *vvs)
{
  gint i = 0;

  while (vvs[i].valstrptr) {
   	if (vvs[i].value == val)
      return(vvs[i].valstrptr);
      i++;
  }

  return(NULL);
}


/************************** Variable declarations **************************/


/* Initialize the protocol and registered fields */
static int proto_wbxml = -1;
static int hf_wbxml_version = -1;
static int hf_wbxml_public_id_known = -1;
static int hf_wbxml_public_id_literal = -1;
static int hf_wbxml_charset = -1;

/* Initialize the subtree pointers */
static gint ett_wbxml = -1;
static gint ett_wbxml_str_tbl = -1;
static gint ett_wbxml_content = -1;


/**************** WBXML related declarations and definitions ****************/


/* WBXML public ID mappings. For an up-to-date list, see
 * http://www.wapforum.org/wina/wbxml-public-docid.htm */
static const value_string vals_wbxml_public_ids[] = {
	/* 0x00 = literal public identifier */
	{ 0x01, "Unknown / missing Public Identifier" },
	{ 0x02, "-//WAPFORUM//DTD WML 1.0//EN (WML 1.0)" },
	{ 0x03, "-//WAPFORUM//DTD WTA 1.0//EN (WTA Event 1.0) - Deprecated" },
	{ 0x04, "-//WAPFORUM//DTD WML 1.1//EN (WML 1.1)" },
	{ 0x05, "-//WAPFORUM//DTD SI 1.0//EN (Service Indication 1.0)" },
	{ 0x06, "-//WAPFORUM//DTD SL 1.0//EN (Service Loading 1.0)" },
	{ 0x07, "-//WAPFORUM//DTD CO 1.0//EN (Cache Operation 1.0)" },
	{ 0x08, "-//WAPFORUM//DTD CHANNEL 1.0//EN (Channel 1.1)" },
	{ 0x09, "-//WAPFORUM//DTD WML 1.2//EN (WML 1.2)" },
	{ 0x0a, "-//WAPFORUM//DTD WML 1.3//EN (WML 1.3)" },
	{ 0x0b, "-//WAPFORUM//DTD PROV 1.0//EN (Provisioning 1.0)" },
	{ 0x0c, "-//WAPFORUM//DTD WTA-WML 1.2//EN (WTA-WML 1.2)" },
	{ 0x0d, "-//WAPFORUM//DTD EMN 1.0//EN (Email Notification 1.0)" },
	{ 0x0e, "-//WAPFORUM//DTD DRMREL 1.0//EN (DRMREL 1.0)" },
	{ 0x0f, "-//WIRELESSVILLAGE//DTD CSP 1.0//EN"
		" (Wireless Village Client-Server Protocol DTD v1.0)" },
	{ 0x10, "-//WIRELESSVILLAGE//DTD CSP 1.1//EN"
		" (Wireless Village Client-Server Protocol DTD v1.1)" },

	/* Registered values - www.syncml.org */
	{ 0x0fd1, "-//SYNCML//DTD SyncML 1.0//EN (SyncML 1.0)" },
	{ 0x0fd3, "-//SYNCML//DTD SyncML 1.1//EN (SyncML 1.1)" },

	/* Registered values - www.wapforum.org/wina/ */
	{ 0x1100, "-//PHONE.COM//DTD ALERT 1.0//EN" },
	{ 0x1101, "-//PHONE.COM//DTD CACHE-OPERATION 1.0//EN" },
	{ 0x1102, "-//PHONE.COM//DTD SIGNAL 1.0//EN" },
	{ 0x1103, "-//PHONE.COM//DTD LIST 1.0//EN" },
	{ 0x1104, "-//PHONE.COM//DTD LISTCMD 1.0//EN" },
	{ 0x1105, "-//PHONE.COM//DTD CHANNEL 1.0//EN" },
	{ 0x1106, "-//PHONE.COM//DTD MMC 1.0//EN" },
	{ 0x1107, "-//PHONE.COM//DTD BEARER-CHOICE 1.0//EN" },
	{ 0x1108, "-//PHONE.COM//DTD WML 1.1//EN (WML+ 1.1)" },
	{ 0x1109, "-//PHONE.COM//DTD CHANNEL 1.1//EN" },
	{ 0x110a, "-//PHONE.COM//DTD LIST 1.1//EN" },
	{ 0x110b, "-//PHONE.COM//DTD LISTCMD 1.1//EN" },
	{ 0x110c, "-//PHONE.COM//DTD MMC 1.1//EN" },
	{ 0x110d, "-//PHONE.COM//DTD WML 1.3//EN (WML+ 1.3)" },
	{ 0x110e, "-//PHONE.COM//DTD MMC 2.0//EN" },
	/* 0x110F -- 0x11FF: unassigned */
	{ 0x1200, "-//3GPP2.COM//DTD IOTA 1.0//EN" },
	
	{ 0x00, NULL }
};

static const value_string vals_wbxml_versions[] = {
	{ 0x00, "1.0" },	/* WAP-104-WBXML */
	{ 0x01, "1.1" },	/* WAP-135-WBXML */
	{ 0x02, "1.2" },	/* WAP-154-WBXML */
	{ 0x03, "1.3" },	/* WAP-192-WBXML */
	
	{ 0x00, NULL }
};

/* WBXML 1.0 global tokens: WAP-104-WBXML
 * Same token mapping as in vals_wbxml1x_global_tokens, but:
 *   { 0xC3, "RESERVED_2" }
 */

/* WBXML 1.x (x>0) global tokens: WAP-135-WBXML, WAP-154-WBXML, WAP-192-WBXML
 */
static const value_string vals_wbxml1x_global_tokens[] = {
	{ 0x00, "SWITCH_PAGE" },
	{ 0x01, "END" },
	{ 0x02, "ENTITY" },
	{ 0x03, "STR_I" },
	{ 0x04, "LITERAL" },

	{ 0x40, "EXT_I_0" },
	{ 0x41, "EXT_I_1" },
	{ 0x42, "EXT_I_2" },
	{ 0x43, "PI" },
	{ 0x44, "LITERAL_C" },

	{ 0x80, "EXT_T_0" },
	{ 0x81, "EXT_T_1" },
	{ 0x82, "EXT_T_2" },
	{ 0x83, "STR_T" },
	{ 0x84, "LITERAL_A" },

	{ 0xC0, "EXT_0" },
	{ 0xC1, "EXT_1" },
	{ 0xC2, "EXT_2" },
	{ 0xC3, "OPAQUE" },
	{ 0xC4, "LITERAL_AC" },

	{ 0x00, NULL }
};


/********************** WBXML token mapping definition **********************/

/*
 * NOTE: Please make sure the Attribute Start values all contain an equal sign
 *       even in cases where they do not contain the start of an Attribute
 *       Value.
 */


/* WML 1.0
 * 
 * Wireless Markup Language
 ***************************************/

/*****   Global extension tokens   *****/
static const value_string wbxml_wmlc10_global_cp0[] = {
	{ 0x40, "Variable substitution - escaped" },
	{ 0x41, "Variable substitution - unescaped" },
	{ 0x42, "Variable substitution - no transformation" },
	{ 0x80, "Variable substitution - escaped" },
	{ 0x81, "Variable substitution - unescaped" },
	{ 0x82, "Variable substitution - no transformation" },
	{ 0xC0, "Reserved" },
	{ 0xC1, "Reserved" },
	{ 0xC2, "Reserved" },

	{ 0x00, NULL }
};

/*****         Tag tokens          *****/
static const value_string wbxml_wmlc10_tags_cp0[] = {
	/* 0x00 -- 0x04 GLOBAL */
	/* 0x05 -- 0xE1 */
	{ 0xE2, "A" },
	{ 0xE3, "ACCESS" },
	{ 0xE4, "B" },
	{ 0xE5, "BIG" },
	{ 0xE6, "BR" },
	{ 0xE7, "CARD" },
	{ 0xE8, "DO" },
	{ 0xE9, "EM" },
	{ 0xEA, "FIELDSET" },
	{ 0xEB, "GO" },
	{ 0xEC, "HEAD" },
	{ 0xED, "I" },
	{ 0xEE, "IMG" },
	{ 0xEF, "INPUT" },
	{ 0xF0, "META" },
	{ 0xF1, "NOOP" },
	{ 0xF2, "PREV" },
	{ 0xF3, "ONEVENT" },
	{ 0xF4, "OPTGROUP" },
	{ 0xF5, "OPTION" },
	{ 0xF6, "REFRESH" },
	{ 0xF7, "SELECT" },
	{ 0xF8, "SMALL" },
	{ 0xF9, "STRONG" },
	{ 0xFA, "TAB" },
	{ 0xFB, "TEMPLATE" },
	{ 0xFC, "TIMER" },
	{ 0xFD, "U" },
	{ 0xFE, "VAR" },
	{ 0xFF, "WML" },

	{ 0x00, NULL }
};

/*****    Attribute Start tokens   *****/
static const value_string wbxml_wmlc10_attrStart_cp0[] = {
	/* 0x00 -- 0x04 GLOBAL */
	{ 0x05, "ACCEPT-CHARSET=" },
	{ 0x06, "ALIGN='BOTTOM'" },
	{ 0x07, "ALIGN='CENTER'" },
	{ 0x08, "ALIGN='LEFT'" },
	{ 0x09, "ALIGN='MIDDLE'" },
	{ 0x0A, "ALIGN='RIGHT'" },
	{ 0x0B, "ALIGN='TOP'" },
	{ 0x0C, "ALT=" },
	{ 0x0D, "CONTENT=" },
	{ 0x0E, "DEFAULT=" },
	{ 0x0F, "DOMAIN=" },
	{ 0x10, "EMPTYOK='FALSE'" },
	{ 0x11, "EMPTYOK='TRUE'" },
	{ 0x12, "FORMAT=" },
	{ 0x13, "HEIGHT=" },
	{ 0x14, "HSPACE=" },
	{ 0x15, "IDEFAULT=" },
	{ 0x16, "IKEY=" },
	{ 0x17, "KEY=" },
	{ 0x18, "LABEL=" },
	{ 0x19, "LOCALSRC=" },
	{ 0x1A, "MAXLENGTH=" },
	{ 0x1B, "METHOD='GET'" },
	{ 0x1C, "METHOD='POST'" },
	{ 0x1D, "MODE='NOWRAP'" },
	{ 0x1E, "MODE='WRAP'" },
	{ 0x1F, "MULTIPLE='FALSE'" },
	{ 0x20, "MULTIPLE='TRUE'" },
	{ 0x21, "NAME=" },
	{ 0x22, "NEWCONTEXT='FALSE'" },
	{ 0x23, "NEWCONTEXT='TRUE'" },
	{ 0x24, "ONCLICK=" },
	{ 0x25, "ONENTERBACKWARD=" },
	{ 0x26, "ONENTERFORWARD=" },
	{ 0x27, "ONTIMER=" },
	{ 0x28, "OPTIONAL='FALSE'" },
	{ 0x29, "OPTIONAL='TRUE'" },
	{ 0x2A, "PATH=" },
	{ 0x2B, "POSTDATA=" },
	{ 0x2C, "PUBLIC='FALSE'" },
	{ 0x2D, "PUBLIC='TRUE'" },
	{ 0x2E, "SCHEME=" },
	{ 0x2F, "SENDREFERER='FALSE'" },
	{ 0x30, "SENDREFERER='TRUE'" },
	{ 0x31, "SIZE=" },
	{ 0x32, "SRC=" },
	{ 0x33, "STYLE='LIST'" },
	{ 0x34, "STYLE='SET'" },
	{ 0x35, "TABINDEX=" },
	{ 0x36, "TITLE=" },
	{ 0x37, "TYPE=" },
	{ 0x38, "TYPE='ACCEPT'" },
	{ 0x39, "TYPE='DELETE'" },
	{ 0x3A, "TYPE='HELP'" },
	{ 0x3B, "TYPE='PASSWORD'" },
	{ 0x3C, "TYPE='ONCLICK'" },
	{ 0x3D, "TYPE='ONENTERBACKWARD'" },
	{ 0x3E, "TYPE='ONENTERFORWARD'" },
	{ 0x3F, "TYPE='ONTIMER'" },
	/* 0x40 -- 0x44 GLOBAL */
	{ 0x45, "TYPE='OPTIONS'" },
	{ 0x46, "TYPE='PREV'" },
	{ 0x47, "TYPE='RESET'" },
	{ 0x48, "TYPE='TEXT'" },
	{ 0x49, "TYPE='vnd.'" },
	{ 0x4A, "URL=" },
	{ 0x4B, "URL='http://'" },
	{ 0x4C, "URL='https://'" },
	{ 0x4D, "USER-AGENT=" },
	{ 0x4E, "VALUE=" },
	{ 0x4F, "VSPACE=" },
	{ 0x50, "WIDTH=" },
	{ 0x51, "xml:lang=" },

	{ 0x00, NULL }
};

/*****    Attribute Value tokens   *****/
static const value_string wbxml_wmlc10_attrValue_cp0[] = {
	/* 0x80 -- 0x84 GLOBAL */
	{ 0x85, "'.com/'" },
	{ 0x86, "'.edu/'" },
	{ 0x87, "'.net/'" },
	{ 0x88, "'.org/'" },
	{ 0x89, "'ACCEPT'" },
	{ 0x8A, "'BOTTOM'" },
	{ 0x8B, "'CLEAR'" },
	{ 0x8C, "'DELETE'" },
	{ 0x8D, "'HELP'" },
	{ 0x8E, "'http://'" },
	{ 0x8F, "'http://www.'" },
	{ 0x90, "'https://'" },
	{ 0x91, "'https://www.'" },
	{ 0x92, "'LIST'" },
	{ 0x93, "'MIDDLE'" },
	{ 0x94, "'NOWRAP'" },
	{ 0x95, "'ONCLICK'" },
	{ 0x96, "'ONENTERBACKWARD'" },
	{ 0x97, "'ONENTERFORWARD'" },
	{ 0x98, "'ONTIMER'" },
	{ 0x99, "'OPTIONS'" },
	{ 0x9A, "'PASSWORD'" },
	{ 0x9B, "'RESET'" },
	{ 0x9C, "'SET'" },
	{ 0x9D, "'TEXT'" },
	{ 0x9E, "'TOP'" },
	{ 0x9F, "'UNKNOWN'" },
	{ 0xA0, "'WRAP'" },
	{ 0xA1, "'www.'" },

	{ 0x00, NULL }
};

/***** Token code page aggregation *****/
static const value_valuestring wbxml_wmlc10_global[] = {
	{ 0, wbxml_wmlc10_global_cp0 },
	{ 0, NULL }
};

static const value_valuestring wbxml_wmlc10_tags[] = {
	{ 0, wbxml_wmlc10_tags_cp0 },
	{ 0, NULL }
};

static const value_valuestring wbxml_wmlc10_attrStart[] = {
	{ 0, wbxml_wmlc10_attrStart_cp0 },
	{ 0, NULL }
};

static const value_valuestring wbxml_wmlc10_attrValue[] = {
	{ 0, wbxml_wmlc10_attrValue_cp0 },
	{ 0, NULL }
};





/* WML 1.1
 * 
 * Wireless Markup Language
 ***************************************/

/*****   Global extension tokens   *****/
/* Same as in WML 1.0 */

/*****         Tag tokens          *****/
static const value_string wbxml_wmlc11_tags_cp0[] = {
	/* 0x00 -- 0x04 GLOBAL */
	/* 0x05 -- 0x1B */
	{ 0x1C, "a" },
	{ 0x1D, "td" },
	{ 0x1E, "tr" },
	{ 0x1F, "table" },
	{ 0x20, "p" },
	{ 0x21, "postfield" },
	{ 0x22, "anchor" },
	{ 0x23, "access" },
	{ 0x24, "b" },
	{ 0x25, "big" },
	{ 0x26, "br" },
	{ 0x27, "card" },
	{ 0x28, "do" },
	{ 0x29, "em" },
	{ 0x2A, "fieldset" },
	{ 0x2B, "go" },
	{ 0x2C, "head" },
	{ 0x2D, "i" },
	{ 0x2E, "img" },
	{ 0x2F, "input" },
	{ 0x30, "meta" },
	{ 0x31, "noop" },
	{ 0x32, "prev" },
	{ 0x33, "onevent" },
	{ 0x34, "optgroup" },
	{ 0x35, "option" },
	{ 0x36, "refresh" },
	{ 0x37, "select" },
	{ 0x38, "small" },
	{ 0x39, "strong" },
	/* 0x3A */
	{ 0x3B, "template" },
	{ 0x3C, "timer" },
	{ 0x3D, "u" },
	{ 0x3E, "setvar" },
	{ 0x3F, "wml" },

	{ 0x00, NULL }
};

/*****    Attribute Start tokens   *****/
static const value_string wbxml_wmlc11_attrStart_cp0[] = {
	/* 0x00 -- 0x04 GLOBAL */
	{ 0x05, "accept-charset=" },
	{ 0x06, "align='bottom'" },
	{ 0x07, "align='center'" },
	{ 0x08, "align='left'" },
	{ 0x09, "align='middle'" },
	{ 0x0A, "align='right'" },
	{ 0x0B, "align='top'" },
	{ 0x0C, "alt=" },
	{ 0x0D, "content=" },
	/* 0x0E */
	{ 0x0F, "domain=" },
	{ 0x10, "emptyok='false'" },
	{ 0x11, "emptyok='true'" },
	{ 0x12, "format=" },
	{ 0x13, "height=" },
	{ 0x14, "hspace=" },
	{ 0x15, "ivalue=" },
	{ 0x16, "iname=" },
	/* 0x17 */
	{ 0x18, "label=" },
	{ 0x19, "localsrc=" },
	{ 0x1A, "maxlength=" },
	{ 0x1B, "method='get'" },
	{ 0x1C, "method='post'" },
	{ 0x1D, "mode='nowrap'" },
	{ 0x1E, "mode='wrap'" },
	{ 0x1F, "multiple='false'" },
	{ 0x20, "multiple='true'" },
	{ 0x21, "name=" },
	{ 0x22, "newcontext='false'" },
	{ 0x23, "newcontext='true'" },
	{ 0x24, "onpick=" },
	{ 0x25, "onenterbackward=" },
	{ 0x26, "onenterforward=" },
	{ 0x27, "ontimer=" },
	{ 0x28, "optional='false'" },
	{ 0x29, "optional='true'" },
	{ 0x2A, "path=" },
	/* 0x2B -- 0x2D */
	{ 0x2E, "scheme=" },
	{ 0x2F, "sendreferer='false'" },
	{ 0x30, "sendreferer='true'" },
	{ 0x31, "size=" },
	{ 0x32, "src=" },
	{ 0x33, "ordered='false'" },
	{ 0x34, "ordered='true'" },
	{ 0x35, "tabindex=" },
	{ 0x36, "title=" },
	{ 0x37, "type=" },
	{ 0x38, "type='accept'" },
	{ 0x39, "type='delete'" },
	{ 0x3A, "type='help'" },
	{ 0x3B, "type='password'" },
	{ 0x3C, "type='onpick'" },
	{ 0x3D, "type='onenterbackward'" },
	{ 0x3E, "type='onenterforward'" },
	{ 0x3F, "type='ontimer'" },
	/* 0x40 -- 0x44 GLOBAL */
	{ 0x45, "type='options'" },
	{ 0x46, "type='prev'" },
	{ 0x47, "type='reset'" },
	{ 0x48, "type='text'" },
	{ 0x49, "type='vnd.'" },
	{ 0x4A, "href=" },
	{ 0x4B, "href='http://'" },
	{ 0x4C, "href='https://'" },
	{ 0x4D, "value=" },
	{ 0x4E, "vspace=" },
	{ 0x4F, "width=" },
	{ 0x50, "xml:lang=" },
	/* 0x51 */
	{ 0x52, "align=" },
	{ 0x53, "columns=" },
	{ 0x54, "class=" },
	{ 0x55, "id=" },
	{ 0x56, "forua='false'" },
	{ 0x57, "forua='true'" },
	{ 0x58, "src='http://'" },
	{ 0x59, "src='https://'" },
	{ 0x5A, "http-equiv=" },
	{ 0x5B, "http-equiv='Content-Type'" },
	{ 0x5C, "content='application/vnd.wap.wmlc;charset='" },
	{ 0x5D, "http-equiv='Expires'" },

	{ 0x00, NULL }
};

/*****    Attribute Value tokens   *****/
static const value_string wbxml_wmlc11_attrValue_cp0[] = {
	/* 0x80 -- 0x84 GLOBAL */
	{ 0x85, "'.com/'" },
	{ 0x86, "'.edu/'" },
	{ 0x87, "'.net/'" },
	{ 0x88, "'.org/'" },
	{ 0x89, "'accept'" },
	{ 0x8A, "'bottom'" },
	{ 0x8B, "'clear'" },
	{ 0x8C, "'delete'" },
	{ 0x8D, "'help'" },
	{ 0x8E, "'http://'" },
	{ 0x8F, "'http://www.'" },
	{ 0x90, "'https://'" },
	{ 0x91, "'https://www.'" },
	/* 0x92 */
	{ 0x93, "'middle'" },
	{ 0x94, "'nowrap'" },
	{ 0x95, "'onpick'" },
	{ 0x96, "'onenterbackward'" },
	{ 0x97, "'onenterforward'" },
	{ 0x98, "'ontimer'" },
	{ 0x99, "'options'" },
	{ 0x9A, "'password'" },
	{ 0x9B, "'reset'" },
	/* 0x9C */
	{ 0x9D, "'text'" },
	{ 0x9E, "'top'" },
	{ 0x9F, "'unknown'" },
	{ 0xA0, "'wrap'" },
	{ 0xA1, "'www.'" },

	{ 0x00, NULL }
};

/***** Token code page aggregation *****/
static const value_valuestring wbxml_wmlc11_global[] = {
	{ 0, wbxml_wmlc10_global_cp0 }, /* Same as WML 1.0 */
	{ 0, NULL }
};

static const value_valuestring wbxml_wmlc11_tags[] = {
	{ 0, wbxml_wmlc11_tags_cp0 },
	{ 0, NULL }
};

static const value_valuestring wbxml_wmlc11_attrStart[] = {
	{ 0, wbxml_wmlc11_attrStart_cp0 },
	{ 0, NULL }
};

static const value_valuestring wbxml_wmlc11_attrValue[] = {
	{ 0, wbxml_wmlc11_attrValue_cp0 },
	{ 0, NULL }
};





/* WML 1.2
 * 
 * Wireless Markup Language
 ***************************************/

/*****   Global extension tokens   *****/
/* Same as in WML 1.0 */

/*****         Tag tokens          *****/
static const value_string wbxml_wmlc12_tags_cp0[] = {
	/* 0x00 -- 0x04 GLOBAL */
	/* 0x05 -- 0x1A */
	{ 0x1B, "pre" },
	{ 0x1C, "a" },
	{ 0x1D, "td" },
	{ 0x1E, "tr" },
	{ 0x1F, "table" },
	{ 0x20, "p" },
	{ 0x21, "postfield" },
	{ 0x22, "anchor" },
	{ 0x23, "access" },
	{ 0x24, "b" },
	{ 0x25, "big" },
	{ 0x26, "br" },
	{ 0x27, "card" },
	{ 0x28, "do" },
	{ 0x29, "em" },
	{ 0x2A, "fieldset" },
	{ 0x2B, "go" },
	{ 0x2C, "head" },
	{ 0x2D, "i" },
	{ 0x2E, "img" },
	{ 0x2F, "input" },
	{ 0x30, "meta" },
	{ 0x31, "noop" },
	{ 0x32, "prev" },
	{ 0x33, "onevent" },
	{ 0x34, "optgroup" },
	{ 0x35, "option" },
	{ 0x36, "refresh" },
	{ 0x37, "select" },
	{ 0x38, "small" },
	{ 0x39, "strong" },
	/* 0x3A */
	{ 0x3B, "template" },
	{ 0x3C, "timer" },
	{ 0x3D, "u" },
	{ 0x3E, "setvar" },
	{ 0x3F, "wml" },

	{ 0x00, NULL }
};

/*****    Attribute Start tokens   *****/
static const value_string wbxml_wmlc12_attrStart_cp0[] = {
	/* 0x00 -- 0x04 GLOBAL */
	{ 0x05, "accept-charset=" },
	{ 0x06, "align='bottom'" },
	{ 0x07, "align='center'" },
	{ 0x08, "align='left'" },
	{ 0x09, "align='middle'" },
	{ 0x0A, "align='right'" },
	{ 0x0B, "align='top'" },
	{ 0x0C, "alt=" },
	{ 0x0D, "content=" },
	/* 0x0E */
	{ 0x0F, "domain=" },
	{ 0x10, "emptyok='false'" },
	{ 0x11, "emptyok='true'" },
	{ 0x12, "format=" },
	{ 0x13, "height=" },
	{ 0x14, "hspace=" },
	{ 0x15, "ivalue=" },
	{ 0x16, "iname=" },
	/* 0x17 */
	{ 0x18, "label=" },
	{ 0x19, "localsrc=" },
	{ 0x1A, "maxlength=" },
	{ 0x1B, "method='get'" },
	{ 0x1C, "method='post'" },
	{ 0x1D, "mode='nowrap'" },
	{ 0x1E, "mode='wrap'" },
	{ 0x1F, "multiple='false'" },
	{ 0x20, "multiple='true'" },
	{ 0x21, "name=" },
	{ 0x22, "newcontext='false'" },
	{ 0x23, "newcontext='true'" },
	{ 0x24, "onpick=" },
	{ 0x25, "onenterbackward=" },
	{ 0x26, "onenterforward=" },
	{ 0x27, "ontimer=" },
	{ 0x28, "optional='false'" },
	{ 0x29, "optional='true'" },
	{ 0x2A, "path=" },
	/* 0x2B -- 0x2D */
	{ 0x2E, "scheme=" },
	{ 0x2F, "sendreferer='false'" },
	{ 0x30, "sendreferer='true'" },
	{ 0x31, "size=" },
	{ 0x32, "src=" },
	{ 0x33, "ordered='false'" },
	{ 0x34, "ordered='true'" },
	{ 0x35, "tabindex=" },
	{ 0x36, "title=" },
	{ 0x37, "type=" },
	{ 0x38, "type='accept'" },
	{ 0x39, "type='delete'" },
	{ 0x3A, "type='help'" },
	{ 0x3B, "type='password'" },
	{ 0x3C, "type='onpick'" },
	{ 0x3D, "type='onenterbackward'" },
	{ 0x3E, "type='onenterforward'" },
	{ 0x3F, "type='ontimer'" },
	/* 0x40 -- 0x44 GLOBAL */
	{ 0x45, "type='options'" },
	{ 0x46, "type='prev'" },
	{ 0x47, "type='reset'" },
	{ 0x48, "type='text'" },
	{ 0x49, "type='vnd.'" },
	{ 0x4A, "href=" },
	{ 0x4B, "href='http://'" },
	{ 0x4C, "href='https://'" },
	{ 0x4D, "value=" },
	{ 0x4E, "vspace=" },
	{ 0x4F, "width=" },
	{ 0x50, "xml:lang=" },
	/* 0x51 */
	{ 0x52, "align=" },
	{ 0x53, "columns=" },
	{ 0x54, "class=" },
	{ 0x55, "id=" },
	{ 0x56, "forua='false'" },
	{ 0x57, "forua='true'" },
	{ 0x58, "src='http://'" },
	{ 0x59, "src='https://'" },
	{ 0x5A, "http-equiv=" },
	{ 0x5B, "http-equiv='Content-Type'" },
	{ 0x5C, "content='application/vnd.wap.wmlc;charset='" },
	{ 0x5D, "http-equiv='Expires'" },
	{ 0x5E, "accesskey=" },
	{ 0x5F, "enctype=" },
	{ 0x60, "enctype='application/x-www-form-urlencoded'" },
	{ 0x61, "enctype='multipart/form-data'" },

	{ 0x00, NULL }
};

/*****    Attribute Value tokens   *****/
/* Same as in WML 1.1 */

/***** Token code page aggregation *****/
static const value_valuestring wbxml_wmlc12_global[] = {
	{ 0, wbxml_wmlc10_global_cp0 }, /* Same as WML 1.0 */
	{ 0, NULL }
};

static const value_valuestring wbxml_wmlc12_tags[] = {
	{ 0, wbxml_wmlc12_tags_cp0 },
	{ 0, NULL }
};

static const value_valuestring wbxml_wmlc12_attrStart[] = {
	{ 0, wbxml_wmlc12_attrStart_cp0 },
	{ 0, NULL }
};

static const value_valuestring wbxml_wmlc12_attrValue[] = {
	{ 0, wbxml_wmlc11_attrValue_cp0 }, /* Same as WML 1.1 */
	{ 0, NULL }
};





/* WML 1.3
 * 
 * Wireless Markup Language
 ***************************************/

/*****   Global extension tokens   *****/
/* Same as in WML 1.0 */

/*****         Tag tokens          *****/
/* Same as in WML 1.2 */

/*****    Attribute Start tokens   *****/
static const value_string wbxml_wmlc13_attrStart_cp0[] = {
	/* 0x00 -- 0x04 GLOBAL */
	{ 0x05, "accept-charset=" },
	{ 0x06, "align='bottom'" },
	{ 0x07, "align='center'" },
	{ 0x08, "align='left'" },
	{ 0x09, "align='middle'" },
	{ 0x0A, "align='right'" },
	{ 0x0B, "align='top'" },
	{ 0x0C, "alt=" },
	{ 0x0D, "content=" },
	/* 0x0E */
	{ 0x0F, "domain=" },
	{ 0x10, "emptyok='false'" },
	{ 0x11, "emptyok='true'" },
	{ 0x12, "format=" },
	{ 0x13, "height=" },
	{ 0x14, "hspace=" },
	{ 0x15, "ivalue=" },
	{ 0x16, "iname=" },
	/* 0x17 */
	{ 0x18, "label=" },
	{ 0x19, "localsrc=" },
	{ 0x1A, "maxlength=" },
	{ 0x1B, "method='get'" },
	{ 0x1C, "method='post'" },
	{ 0x1D, "mode='nowrap'" },
	{ 0x1E, "mode='wrap'" },
	{ 0x1F, "multiple='false'" },
	{ 0x20, "multiple='true'" },
	{ 0x21, "name=" },
	{ 0x22, "newcontext='false'" },
	{ 0x23, "newcontext='true'" },
	{ 0x24, "onpick=" },
	{ 0x25, "onenterbackward=" },
	{ 0x26, "onenterforward=" },
	{ 0x27, "ontimer=" },
	{ 0x28, "optional='false'" },
	{ 0x29, "optional='true'" },
	{ 0x2A, "path=" },
	/* 0x2B -- 0x2D */
	{ 0x2E, "scheme=" },
	{ 0x2F, "sendreferer='false'" },
	{ 0x30, "sendreferer='true'" },
	{ 0x31, "size=" },
	{ 0x32, "src=" },
	{ 0x33, "ordered='false'" },
	{ 0x34, "ordered='true'" },
	{ 0x35, "tabindex=" },
	{ 0x36, "title=" },
	{ 0x37, "type=" },
	{ 0x38, "type='accept'" },
	{ 0x39, "type='delete'" },
	{ 0x3A, "type='help'" },
	{ 0x3B, "type='password'" },
	{ 0x3C, "type='onpick'" },
	{ 0x3D, "type='onenterbackward'" },
	{ 0x3E, "type='onenterforward'" },
	{ 0x3F, "type='ontimer'" },
	/* 0x40 -- 0x44 GLOBAL */
	{ 0x45, "type='options'" },
	{ 0x46, "type='prev'" },
	{ 0x47, "type='reset'" },
	{ 0x48, "type='text'" },
	{ 0x49, "type='vnd.'" },
	{ 0x4A, "href=" },
	{ 0x4B, "href='http://'" },
	{ 0x4C, "href='https://'" },
	{ 0x4D, "value=" },
	{ 0x4E, "vspace=" },
	{ 0x4F, "width=" },
	{ 0x50, "xml:lang=" },
	/* 0x51 */
	{ 0x52, "align=" },
	{ 0x53, "columns=" },
	{ 0x54, "class=" },
	{ 0x55, "id=" },
	{ 0x56, "forua='false'" },
	{ 0x57, "forua='true'" },
	{ 0x58, "src='http://'" },
	{ 0x59, "src='https://'" },
	{ 0x5A, "http-equiv=" },
	{ 0x5B, "http-equiv='Content-Type'" },
	{ 0x5C, "content='application/vnd.wap.wmlc;charset='" },
	{ 0x5D, "http-equiv='Expires'" },
	{ 0x5E, "accesskey=" },
	{ 0x5F, "enctype=" },
	{ 0x60, "enctype='application/x-www-form-urlencoded'" },
	{ 0x61, "enctype='multipart/form-data'" },
	{ 0x62, "xml:space='preserve'" },
	{ 0x63, "xml:space='default'" },
	{ 0x64, "cache-control='no-cache'" },

	{ 0x00, NULL }
};

/*****    Attribute Value tokens   *****/
/* Same as in WML 1.1 */

/***** Token code page aggregation *****/
static const value_valuestring wbxml_wmlc13_global[] = {
	{ 0, wbxml_wmlc10_global_cp0 }, /* Same as WML 1.0 */
	{ 0, NULL }
};

static const value_valuestring wbxml_wmlc13_tags[] = {
	{ 0, wbxml_wmlc12_tags_cp0 },
	{ 0, NULL }
};

static const value_valuestring wbxml_wmlc13_attrStart[] = {
	{ 0, wbxml_wmlc13_attrStart_cp0 },
	{ 0, NULL }
};

static const value_valuestring wbxml_wmlc13_attrValue[] = {
	{ 0, wbxml_wmlc11_attrValue_cp0 }, /* Same as WML 1.1 */
	{ 0, NULL }
};





/* SI 1.0
 * 
 * Service Indication
 ***************************************/

/*****   Global extension tokens   *****/

/*****         Tag tokens          *****/
static const value_string wbxml_sic10_tags_cp0[] = {
	/* 0x00 -- 0x04 GLOBAL */
	{ 0x05, "si" },
	{ 0x06, "indication" },
	{ 0x07, "info" },
	{ 0x08, "item" },

	{ 0x00, NULL }
};

/*****    Attribute Start tokens   *****/
static const value_string wbxml_sic10_attrStart_cp0[] = {
	/* 0x00 -- 0x04 GLOBAL */
	{ 0x05, "action='signal-none'" },
	{ 0x06, "action='signal-low'" },
	{ 0x07, "action='signal-medium'" },
	{ 0x08, "action='signal-high'" },
	{ 0x09, "action='delete'" },
	{ 0x0a, "created=" },
	{ 0x0b, "href=" },
	{ 0x0c, "href='http://'" },
	{ 0x0d, "href='http://www.'" },
	{ 0x0e, "href='https://'" },
	{ 0x0f, "href='https://www.'" },
	{ 0x10, "si-expires=" },
	{ 0x11, "si-id=" },
	{ 0x12, "class=" },

	{ 0x00, NULL }
};

/*****    Attribute Value tokens   *****/
static const value_string wbxml_sic10_attrValue_cp0[] = {
	/* 0x80 -- 0x84 GLOBAL */
	{ 0x85, "'.com/'" },
	{ 0x86, "'.edu/'" },
	{ 0x87, "'.net/'" },
	{ 0x88, "'.org/'" },

	{ 0x00, NULL }
};

/***** Token code page aggregation *****/
static const value_valuestring wbxml_sic10_tags[] = {
	{ 0, wbxml_sic10_tags_cp0 },
	{ 0, NULL }
};

static const value_valuestring wbxml_sic10_attrStart[] = {
	{ 0, wbxml_sic10_attrStart_cp0 },
	{ 0, NULL }
};

static const value_valuestring wbxml_sic10_attrValue[] = {
	{ 0, wbxml_sic10_attrValue_cp0 },
	{ 0, NULL }
};





/* SL 1.0
 * 
 * Service Loading
 ***************************************/

/*****   Global extension tokens   *****/

/*****         Tag tokens          *****/
static const value_string wbxml_slc10_tags_cp0[] = {
	/* 0x00 -- 0x04 GLOBAL */
	{ 0x05, "sl" },

	{ 0x00, NULL }
};

/*****    Attribute Start tokens   *****/
static const value_string wbxml_slc10_attrStart_cp0[] = {
	/* 0x00 -- 0x04 GLOBAL */
	{ 0x05, "action='execute-low'" },
	{ 0x06, "action='execute-high'" },
	{ 0x07, "action='cache'" },
	{ 0x08, "href=" },
	{ 0x09, "href='http://'" },
	{ 0x0a, "href='http://www.'" },
	{ 0x0b, "href='https://'" },
	{ 0x0c, "href='https://www.'" },

	{ 0x00, NULL }
};

/*****    Attribute Value tokens   *****/
/* Same as in SI 1.0 */

/***** Token code page aggregation *****/
static const value_valuestring wbxml_slc10_tags[] = {
	{ 0, wbxml_slc10_tags_cp0 },
	{ 0, NULL }
};

static const value_valuestring wbxml_slc10_attrStart[] = {
	{ 0, wbxml_slc10_attrStart_cp0 },
	{ 0, NULL }
};

static const value_valuestring wbxml_slc10_attrValue[] = {
	{ 0, wbxml_sic10_attrValue_cp0 }, /* Same as SI 1.0 */
	{ 0, NULL }
};





/* CO 1.0
 * 
 * Cache Operation
 ***************************************/

/*****   Global extension tokens   *****/

/*****         Tag tokens          *****/
static const value_string wbxml_coc10_tags_cp0[] = {
	/* 0x00 -- 0x04 GLOBAL */
	{ 0x05, "co" },
	{ 0x06, "invalidate-object" },
	{ 0x07, "invalidate-service" },

	{ 0x00, NULL }
};

/*****    Attribute Start tokens   *****/
static const value_string wbxml_coc10_attrStart_cp0[] = {
	/* 0x00 -- 0x04 GLOBAL */
	{ 0x05, "uri=" },
	{ 0x06, "uri='http://'" },
	{ 0x07, "uri='http://www.'" },
	{ 0x08, "uri='https://'" },
	{ 0x09, "uri='https://www.'" },

	{ 0x00, NULL }
};

/*****    Attribute Value tokens   *****/
/* Same as in SI 1.0 */

/***** Token code page aggregation *****/
static const value_valuestring wbxml_coc10_tags[] = {
	{ 0, wbxml_coc10_tags_cp0 },
	{ 0, NULL }
};

static const value_valuestring wbxml_coc10_attrStart[] = {
	{ 0, wbxml_coc10_attrStart_cp0 },
	{ 0, NULL }
};

static const value_valuestring wbxml_coc10_attrValue[] = {
	{ 0, wbxml_sic10_attrValue_cp0 }, /* Same as SI 1.0 */
	{ 0, NULL }
};





/* PROV 1.0
 *
 * Client Provisioning
 ***************************************/

/*****   Global extension tokens   *****/

/*****         Tag tokens          *****/
static const value_string wbxml_provc10_tags_cp0[] = {
	/* 0x00 -- 0x04 GLOBAL */
	{ 0x05, "wap-provisioningdoc" },
	{ 0x06, "characteristic" },
	{ 0x07, "parm" },

	{ 0x00, NULL }
};
static const value_string wbxml_provc10_tags_cp1[] = {
	/* 0x00 -- 0x04 GLOBAL */
	/* 0x05 */
	{ 0x06, "characteristic" },
	{ 0x07, "parm" },

	{ 0x00, NULL }
};

/*****    Attribute Start tokens   *****/
static const value_string wbxml_provc10_attrStart_cp0[] = {
	/* 0x00 -- 0x04 GLOBAL */
	{ 0x05, "name=" },
	{ 0x06, "value=" },
	{ 0x07, "name='NAME'" },
	{ 0x08, "name='NAP-ADDRESS'" },
	{ 0x09, "name='NAP-ADDRTYPE'" },
	{ 0x0A, "name='CALLTYPE'" },
	{ 0x0B, "name='VALIDUNTIL'" },
	{ 0x0C, "name='AUTHTYPE'" },
	{ 0x0D, "name='AUTHNAME'" },
	{ 0x0E, "name='AUTHSECRET'" },
	{ 0x0F, "name='LINGER'" },
	{ 0x10, "name='BEARER'" },
	{ 0x11, "name='NAPID'" },
	{ 0x12, "name='COUNTRY'" },
	{ 0x13, "name='NETWORK'" },
	{ 0x14, "name='INTERNET'" },
	{ 0x15, "name='PROXY-ID'" },
	{ 0x16, "name='PROXY-PROVIDER-ID'" },
	{ 0x17, "name='DOMAIN'" },
	{ 0x18, "name='PROVURL'" },
	{ 0x19, "name='PXAUTH-TYPE'" },
	{ 0x1A, "name='PXAUTH-ID'" },
	{ 0x1B, "name='PXAUTH-PW'" },
	{ 0x1C, "name='STARTPAGE'" },
	{ 0x1D, "name='BASAUTH-ID'" },
	{ 0x1E, "name='BASAUTH-PW'" },
	{ 0x1F, "name='PUSHENABLED'" },
	{ 0x20, "name='PXADDR'" },
	{ 0x21, "name='PXADDRTYPE'" },
	{ 0x22, "name='TO-NAPID'" },
	{ 0x23, "name='PORTNBR'" },
	{ 0x24, "name='SERVICE'" },
	{ 0x25, "name='LINKSPEED'" },
	{ 0x26, "name='DNLINKSPEED'" },
	{ 0x27, "name='LOCAL-ADDR'" },
	{ 0x28, "name='LOCAL-ADDRTYPE'" },
	{ 0x29, "name='CONTEXT-ALLOW'" },
	{ 0x2A, "name='TRUST'" },
	{ 0x2B, "name='MASTER'" },
	{ 0x2C, "name='SID'" },
	{ 0x2D, "name='SOC'" },
	{ 0x2E, "name='WSP-VERSION'" },
	{ 0x2F, "name='PHYSICAL-PROXY-ID'" },
	{ 0x30, "name='CLIENT-ID'" },
	{ 0x31, "name='DELIVERY-ERR-SDU'" },
	{ 0x32, "name='DELIVERY-ORDER'" },
	{ 0x33, "name='TRAFFIC-CLASS'" },
	{ 0x34, "name='MAX-SDU-SIZE'" },
	{ 0x35, "name='MAX-BITRATE-UPLINK'" },
	{ 0x36, "name='MAX-BITRATE-DNLINK'" },
	{ 0x37, "name='RESIDUAL-BER'" },
	{ 0x38, "name='SDU-ERROR-RATIO'" },
	{ 0x39, "name='TRAFFIC-HANDL-PRIO'" },
	{ 0x3A, "name='TRANSFER-DELAY'" },
	{ 0x3B, "name='GUARANTEED-BITRATE-UPLINK'" },
	{ 0x3C, "name='GUARANTEED-BITRATE-DNLINK'" },
	{ 0x3D, "name='PXADDR-FQDN'" },
	{ 0x3E, "name='PROXY-PW'" },
	{ 0x3F, "name='PPGAUTH-TYPE'" },
	/* 0x40 -- 0x44 GLOBAL */
	{ 0x45, "version=" },
	{ 0x46, "version='1.0'" },
	{ 0x47, "name='PULLENABLED'" },
	{ 0x48, "name='DNS-ADDR'" },
	{ 0x49, "name='MAX-NUM-RETRY'" },
	{ 0x4A, "name='FIRST-RETRY-TIMEOUT'" },
	{ 0x4B, "name='REREG-THRESHOLD'" },
	{ 0x4C, "name='T-BIT'" },
	/* 0x4D */
	{ 0x4E, "name='AUTH-ENTITY'" },
	{ 0x4F, "name='SPI'" },
	{ 0x50, "type=" },
	{ 0x51, "type='PXLOGICAL'" },
	{ 0x52, "type='PXPHYSICAL'" },
	{ 0x53, "type='PORT'" },
	{ 0x54, "type='VALIDITY'" },
	{ 0x55, "type='NAPDEF'" },
	{ 0x56, "type='BOOTSTRAP'" },
	{ 0x57, "type='VENDORCONFIG'" },
	{ 0x58, "type='CLIENTIDENTITY'" },
	{ 0x59, "type='PXAUTHINFO'" },
	{ 0x5A, "type='NAPAUTHINFO'" },
	{ 0x5B, "type='ACCESS'" },

	{ 0x00, NULL }
};
static const value_string wbxml_provc10_attrStart_cp1[] = {
	/* 0x00 -- 0x04 GLOBAL */
	/* 0x05 -- 0x06 */
	{ 0x07, "name='NAME'" },
	/* 0x08 -- 0x13 */
	{ 0x14, "name='INTERNET'" },
	/* 0x15 -- 0x1B */
	{ 0x1C, "name='STARTPAGE'" },
	/* 0x1D -- 0x21 */
	{ 0x22, "name='TO-NAPID'" },
	{ 0x23, "name='PORTNBR'" },
	{ 0x24, "name='SERVICE'" },
	/* 0x25 -- 0x2D */
	{ 0x2E, "name='AACCEPT'" },
	{ 0x2F, "name='AAUTHDATA'" },
	{ 0x30, "name='AAUTHLEVEL'" },
	{ 0x31, "name='AAUTHNAME'" },
	{ 0x32, "name='AAUTHSECRET'" },
	{ 0x33, "name='AAUTHTYPE'" },
	{ 0x34, "name='ADDR'" },
	{ 0x35, "name='ADDRTYPE'" },
	{ 0x36, "name='APPID'" },
	{ 0x37, "name='APROTOCOL'" },
	{ 0x38, "name='PROVIDER-ID'" },
	{ 0x39, "name='TO-PROXY'" },
	{ 0x3A, "name='URI'" },
	{ 0x3B, "name='RULE'" },
	/* 0x3C -- 0x3F */
	/* 0x40 -- 0x44 GLOBAL */
	/* 0x45 -- 0x4F */
	{ 0x50, "type=" },
	/* 0x51 -- 0x52 */
	{ 0x53, "type='PORT'" },
	/* 0x54 */
	{ 0x55, "type='APPLICATION'" },
	{ 0x56, "type='APPADDR'" },
	{ 0x57, "type='APPAUTH'" },
	{ 0x58, "type='CLIENTIDENTITY'" },
	{ 0x59, "type='RESOURCE'" },
	/* 0x5A -- 0x7F */

	{ 0x00, NULL }
};

/*****    Attribute Start tokens   *****/
static const value_string wbxml_provc10_attrValue_cp0[] = {
	/* 0x80 -- 0x84 GLOBAL */
	{ 0x85, "'IPV4'" },
	{ 0x86, "'IPV6'" },
	{ 0x87, "'E164'" },
	{ 0x88, "'ALPHA'" },
	{ 0x89, "'APN'" },
	{ 0x8A, "'SCODE'" },
	{ 0x8B, "'TETRA-ITSI'" },
	{ 0x8C, "'MAN'" },
	/* 0x8D -- 0x8F */
	{ 0x90, "'ANALOG-MODEM'" },
	{ 0x91, "'V.120'" },
	{ 0x92, "'V.110'" },
	{ 0x93, "'X.31'" },
	{ 0x94, "'BIT-TRANSPARENT'" },
	{ 0x95, "'DIRECT-ASYNCHRONOUS-DATA-SERVICE'" },
	/* 0x96 -- 0x99 */
	{ 0x9A, "'PAP'" },
	{ 0x9B, "'CHAP'" },
	{ 0x9C, "'HTTP-BASIC'" },
	{ 0x9D, "'HTTP-DIGEST'" },
	{ 0x9E, "'WTLS-SS'" },
	{ 0x9F, "'MD5'" },
	/* 0xA0 -- 0xA1 */
	{ 0xA2, "'GSM-USSD'" },
	{ 0xA3, "'GSM-SMS'" },
	{ 0xA4, "'ANSI-136-GUTS'" },
	{ 0xA5, "'IS-95-CDMA-SMS'" },
	{ 0xA6, "'IS-95-CDMA-CSD'" },
	{ 0xA7, "'IS-95-CDMA-PACKET'" },
	{ 0xA8, "'ANSI-136-CSD'" },
	{ 0xA9, "'ANSI-136-GPRS'" },
	{ 0xAA, "'GSM-CSD'" },
	{ 0xAB, "'GSM-GPRS'" },
	{ 0xAC, "'AMPS-CDPD'" },
	{ 0xAD, "'PDC-CSD'" },
	{ 0xAE, "'PDC-PACKET'" },
	{ 0xAF, "'IDEN-SMS'" },
	{ 0xB0, "'IDEN-CSD'" },
	{ 0xB1, "'IDEN-PACKET'" },
	{ 0xB2, "'FLEX/REFLEX'" },
	{ 0xB3, "'PHS-SMS'" },
	{ 0xB4, "'PHS-CSD'" },
	{ 0xB5, "'TETRA-SDS'" },
	{ 0xB6, "'TETRA-PACKET'" },
	{ 0xB7, "'ANSI-136-GHOST'" },
	{ 0xB8, "'MOBITEX-MPAK'" },
	{ 0xB9, "'CDMA2000-IX-SIMPLE-IP'" },
	{ 0xBA, "'CDMA2000-IX-MOBILE-IP'" },
	/* 0xBB -- 0xBF */
	/* 0xC0 -- 0xC4 GLOBAL */
	{ 0xC5, "'AUTOBAUDING'" },
	/* 0xC6 -- 0xC9 */
	{ 0xCA, "'CL-WSP'" },
	{ 0xCB, "'CO-WSP'" },
	{ 0xCC, "'CL-SEC-WSP'" },
	{ 0xCD, "'CO-SEC-WSP'" },
	{ 0xCE, "'CL-SEC-WTA'" },
	{ 0xCF, "'CO-SEC-WTA'" },
	{ 0xD0, "'OTA-HTTP-TO'" },
	{ 0xD1, "'OTA-HTTP-TLS-TO'" },
	{ 0xD2, "'OTA-HTTP-PO'" },
	{ 0xD3, "'OTA-HTTP-TLS-PO'" },
	/* 0xD4 -- 0xFF */

	{ 0x00, NULL }
};
static const value_string wbxml_provc10_attrValue_cp1[] = {
	/* 0x80 -- 0x84 GLOBAL */
	/* 0x85 */
	{ 0x86, "'IPV6'" },
	{ 0x87, "'E164'" },
	{ 0x88, "'ALPHA'" },
	{ 0x8D, "'APPSRV'" },
	{ 0x8E, "'OBEX'" },
	/* 0x8F */

	/* XXX - Errors that require a fix in the OMA/WAP Client Provisioning specs:
	{ 0xXXX, "','" },
	{ 0xXXX, "'HTTP-'" },
	{ 0xXXX, "'BASIC'" },
	{ 0xXXX, "'DIGEST'" },
	*/

	{ 0xE0, "'AAA'" },
	{ 0xE1, "'HA'" },

	{ 0x00, NULL }
};

/***** Token code page aggregation *****/
static const value_valuestring wbxml_provc10_tags[] = {
	{ 0, wbxml_provc10_tags_cp0 },
	{ 1, wbxml_provc10_tags_cp1 },
	{ 0, NULL }
};

static const value_valuestring wbxml_provc10_attrStart[] = {
	{ 0, wbxml_provc10_attrStart_cp0 },
	{ 1, wbxml_provc10_attrStart_cp1 },
	{ 0, NULL }
};

static const value_valuestring wbxml_provc10_attrValue[] = {
	{ 0, wbxml_provc10_attrValue_cp0 },
	{ 1, wbxml_provc10_attrValue_cp1 },
	{ 0, NULL }
};





/* EMN 1.0
 * 
 * Email Notification
 ***************************************/

/*****   Global extension tokens   *****/

/*****         Tag tokens          *****/
static const value_string wbxml_emnc10_tags_cp0[] = {
	/* 0x00 -- 0x04 GLOBAL */
	{ 0x05, "emn" },

	{ 0x00, NULL }
};

/*****    Attribute Start tokens   *****/
static const value_string wbxml_emnc10_attrStart_cp0[] = {
	/* 0x00 -- 0x04 GLOBAL */
	{ 0x05, "timestamp=" },
	{ 0x06, "mailbox=" },
	{ 0x07, "mailbox='mailat:'" },
	{ 0x08, "mailbox='pop://'" },
	{ 0x09, "mailbox='imap://'" },
	{ 0x0a, "mailbox='http://'" },
	{ 0x0b, "mailbox='http://www.'" },
	{ 0x0c, "mailbox='https://'" },
	{ 0x0D, "mailbox='https://www.'" },

	{ 0x00, NULL }
};

/*****    Attribute Value tokens   *****/
/* Same as in SI 1.0 */

/***** Token code page aggregation *****/
static const value_valuestring wbxml_emnc10_tags[] = {
	{ 0, wbxml_emnc10_tags_cp0 },
	{ 0, NULL }
};

static const value_valuestring wbxml_emnc10_attrStart[] = {
	{ 0, wbxml_emnc10_attrStart_cp0 },
	{ 0, NULL }
};

static const value_valuestring wbxml_emnc10_attrValue[] = {
	{ 0, wbxml_sic10_attrValue_cp0 }, /* Same as SI 1.0 */
	{ 0, NULL }
};





/* SyncML 1.0
 * 
 * SyncML Representation Protocol
 ***************************************/

/*****   Global extension tokens   *****/

/*****         Tag tokens          *****/
static const value_string wbxml_syncmlc10_tags_cp0[] = { /* SyncML 1.0 */
	/* 0x00 -- 0x04 GLOBAL */
	{ 0x05, "Add" },
	{ 0x06, "Alert" },
	{ 0x07, "Archive" },
	{ 0x08, "Atomic" },
	{ 0x09, "Chal" },
	{ 0x0A, "Cmd" },
	{ 0x0B, "CmdID" },
	{ 0x0C, "CmdRef" },
	{ 0x0D, "Copy" },
	{ 0x0E, "Cred" },
	{ 0x0F, "Data" },
	{ 0x10, "Delete" },
	{ 0x11, "Exec" },
	{ 0x12, "Final" },
	{ 0x13, "Get" },
	{ 0x14, "Item" },
	{ 0x15, "Lang" },
	{ 0x16, "LocName" },
	{ 0x17, "LocURI" },
	{ 0x18, "Map" },
	{ 0x19, "MapItem" },
	{ 0x1A, "Meta" },
	{ 0x1B, "MsgID" },
	{ 0x1C, "MsgRef" },
	{ 0x1D, "NoResp" },
	{ 0x1E, "NoResults" },
	{ 0x1F, "Put" },
	{ 0x20, "Replace" },
	{ 0x21, "RespURI" },
	{ 0x22, "Results" },
	{ 0x23, "Search" },
	{ 0x24, "Sequence" },
	{ 0x25, "SessionID" },
	{ 0x26, "SftDel" },
	{ 0x27, "Source" },
	{ 0x28, "SourceRef" },
	{ 0x29, "Status" },
	{ 0x2A, "Sync" },
	{ 0x2B, "SyncBody" },
	{ 0x2C, "SyncHdr" },
	{ 0x2D, "SyncML" },
	{ 0x2E, "Target" },
	{ 0x2F, "TargetRef" },
	/* 0x30 - Reserved */
	{ 0x31, "VerDTD" },
	{ 0x32, "VerProto" },

	{ 0x00, NULL }
};

static const value_string wbxml_syncmlc10_tags_cp1[] = { /* MetInf 1.0 */
	/* 0x00 -- 0x04 GLOBAL */
	{ 0x05, "Anchor" },
	{ 0x06, "EMI" },
	{ 0x07, "Format" },
	{ 0x08, "FreeID" },
	{ 0x09, "FreeMem" },
	{ 0x0A, "Last" },
	{ 0x0B, "Mark" },
	{ 0x0C, "MaxMsgSize" },
	{ 0x0D, "Mem" },
	{ 0x0E, "MetInf" },
	{ 0x0F, "Next" },
	{ 0x10, "NextNonce" },
	{ 0x11, "SharedMem" },
	{ 0x12, "Size" },
	{ 0x13, "Type" },
	{ 0x14, "Version" },

	{ 0x00, NULL }
};

/*****    Attribute Start tokens   *****/

/*****    Attribute Value tokens   *****/

/***** Token code page aggregation *****/
static const value_valuestring wbxml_syncmlc10_tags[] = {
	{ 0, wbxml_syncmlc10_tags_cp0 }, /* -//SYNCML//DTD SyncML 1.0//EN */
	{ 1, wbxml_syncmlc10_tags_cp1 }, /* -//SYNCML//DTD MetInf 1.0//EN */
	{ 0, NULL }
};





/* SyncML 1.1
 * 
 * SyncML Representation Protocol
 ***************************************/

/*****   Global extension tokens   *****/

/*****         Tag tokens          *****/
static const value_string wbxml_syncmlc11_tags_cp0[] = { /* SyncML 1.1 */
	/* 0x00 -- 0x04 GLOBAL */
	{ 0x05, "Add" },
	{ 0x06, "Alert" },
	{ 0x07, "Archive" },
	{ 0x08, "Atomic" },
	{ 0x09, "Chal" },
	{ 0x0a, "Cmd" },
	{ 0x0b, "CmdID" },
	{ 0x0c, "CmdRef" },
	{ 0x0d, "Copy" },
	{ 0x0e, "Cred" },
	{ 0x0f, "Data" },
	{ 0x10, "Delete" },
	{ 0x11, "Exec" },
	{ 0x12, "Final" },
	{ 0x13, "Get" },
	{ 0x14, "Item" },
	{ 0x15, "Lang" },
	{ 0x16, "LocName" },
	{ 0x17, "LocURI" },
	{ 0x18, "Map" },
	{ 0x19, "MapItem" },
	{ 0x1a, "Meta" },
	{ 0x1b, "MsgID" },
	{ 0x1c, "MsgRef" },
	{ 0x1d, "NoResp" },
	{ 0x1e, "NoResults" },
	{ 0x1f, "Put" },
	{ 0x20, "Replace" },
	{ 0x21, "RespURI" },
	{ 0x22, "Results" },
	{ 0x23, "Search" },
	{ 0x24, "Sequence" },
	{ 0x25, "SessionID" },
	{ 0x26, "SftDel" },
	{ 0x27, "Source" },
	{ 0x28, "SourceRef" },
	{ 0x29, "Status" },
	{ 0x2a, "Sync" },
	{ 0x2b, "SyncBody" },
	{ 0x2c, "SyncHdr" },
	{ 0x2d, "SyncML" },
	{ 0x2e, "Target" },
	{ 0x2f, "TargetRef" },
	/* 0x30 - Reserved */
	{ 0x31, "VerDTD" },
	{ 0x32, "VerProto" },
	{ 0x33, "NumberOfChanges" },
	{ 0x34, "MoreData" },

	{ 0x00, NULL }
};

static const value_string wbxml_syncmlc11_tags_cp1[] = { /* MetInf 1.1 */
	/* 0x00 -- 0x04 GLOBAL */
	{ 0x05, "Anchor" },
	{ 0x06, "EMI" },
	{ 0x07, "Format" },
	{ 0x08, "FreeID" },
	{ 0x09, "FreeMem" },
	{ 0x0A, "Last" },
	{ 0x0B, "Mark" },
	{ 0x0C, "MaxMsgSize" },
	{ 0x0D, "Mem" },
	{ 0x0E, "MetInf" },
	{ 0x0F, "Next" },
	{ 0x10, "NextNonce" },
	{ 0x11, "SharedMem" },
	{ 0x12, "Size" },
	{ 0x13, "Type" },
	{ 0x14, "Version" },
	{ 0x15, "MaxObjSize" },

	{ 0x00, NULL }
};

/*****    Attribute Start tokens   *****/

/*****    Attribute Value tokens   *****/

/***** Token code page aggregation *****/
static const value_valuestring wbxml_syncmlc11_tags[] = {
	{ 0, wbxml_syncmlc11_tags_cp0 }, /* -//SYNCML//DTD SyncML 1.1//EN */
	{ 1, wbxml_syncmlc11_tags_cp1 }, /* -//SYNCML//DTD MetInf 1.1//EN */
	{ 0, NULL }
};





/* CHANNEL 1.0
 * 
 * WTA Channel
 ***************************************/

/*****   Global extension tokens   *****/

/*****         Tag tokens          *****/
static const value_string wbxml_channelc10_tags_cp0[] = {
	/* 0x00 -- 0x04 GLOBAL */
	{ 0x05, "channel" },
	{ 0x06, "title" },
	{ 0x07, "abstract" },
	{ 0x08, "resource" },

	{ 0x00, NULL }
};

/*****    Attribute Start tokens   *****/
static const value_string wbxml_channelc10_attrStart_cp0[] = {
	/* 0x00 -- 0x04 GLOBAL */
	{ 0x05, "maxspace=" },
	{ 0x06, "base=" },
	{ 0x07, "href=" },
	{ 0x08, "href='http://'" },
	{ 0x09, "href='https://'" },
	{ 0x0A, "lastmod=" },
	{ 0x0B, "etag=" },
	{ 0x0C, "md5=" },
	{ 0x0D, "success=" },
	{ 0x0E, "success='http://'" },
	{ 0x0F, "success='https://'" },
	{ 0x10, "failure=" },
	{ 0x11, "failure='http://'" },
	{ 0x12, "failure='https://'" },
	{ 0x13, "EventId=" },

	{ 0x00, NULL }
};

/*****    Attribute Value tokens   *****/

/***** Token code page aggregation *****/
static const value_valuestring wbxml_channelc10_tags[] = {
	{ 0, wbxml_channelc10_tags_cp0 },
	{ 0, NULL }
};

static const value_valuestring wbxml_channelc10_attrStart[] = {
	{ 0, wbxml_channelc10_attrStart_cp0 },
	{ 0, NULL }
};





/* application/x-wap-prov.browser-settings
 * application/x-wap-prov.browser-bookmarks
 * 
 * Nokia OTA Provisioning document format
 ***************************************/

/*****   Global extension tokens   *****/

/*****         Tag tokens          *****/
static const value_string wbxml_nokiaprovc70_tags_cp0[] = {
	/* 0x00 -- 0x04 GLOBAL */
	{ 0x05, "CHARACTERISTIC-LIST" },
	{ 0x06, "CHARACTERISTIC" },
	{ 0x07, "PARM" },

	{ 0x00, NULL }
};

/*****    Attribute Start tokens   *****/
static const value_string wbxml_nokiaprovc70_attrStart_cp0[] = {
	/* 0x00 -- 0x04 GLOBAL */
	{ 0x06, "TYPE='ADDRESS'" },
	{ 0x07, "TYPE='URL'" },
	{ 0x08, "TYPE='NAME'" },
	{ 0x10, "NAME=" },
	{ 0x11, "VALUE=" },
	{ 0x12, "NAME='BEARER'" },
	{ 0x13, "NAME='PROXY'" },
	{ 0x14, "NAME='PORT'" },
	{ 0x15, "NAME='NAME'" },
	{ 0x16, "NAME='PROXY_TYPE'" },
	{ 0x17, "NAME='URL'" },
	{ 0x18, "NAME='PROXY_AUTHNAME'" },
	{ 0x19, "NAME='PROXY_AUTHSECRET'" },
	{ 0x1A, "NAME='SMS_SMSC_ADDRESS'" },
	{ 0x1B, "NAME='USSD_SERVICE_CODE'" },
	{ 0x1C, "NAME='GPRS_ACCESSPOINTNAME'" },
	{ 0x1D, "NAME='PPP_LOGINTYPE'" },
	{ 0x1E, "NAME='PROXY_LOGINTYPE'" },
	{ 0x21, "NAME='CSD_DIALSTRING'" },
	{ 0x22, "NAME='PPP_AUTHTYPE'" },
	{ 0x23, "NAME='PPP_AUTHNAME'" },
	{ 0x24, "NAME='PPP_AUTHSECRET'" },
	{ 0x28, "NAME='CSD_CALLTYPE'" },
	{ 0x29, "NAME='CSD_CALLSPEED'" },
	{ 0x45, "VALUE='GSM/CSD'" },
	{ 0x46, "VALUE='GSM/SMS'" },
	{ 0x47, "VALUE='GSM/USSD'" },
	{ 0x48, "VALUE='IS-136/CSD'" },
	{ 0x49, "VALUE='GPRS'" },
	{ 0x60, "VALUE='9200'" },
	{ 0x61, "VALUE='9201'" },
	{ 0x62, "VALUE='9202'" },
	{ 0x63, "VALUE='9203'" },
	{ 0x64, "VALUE='AUTOMATIC'" },
	{ 0x65, "VALUE='MANUAL'" },
	{ 0x6A, "VALUE='AUTO'" },
	{ 0x6B, "VALUE='9600'" },
	{ 0x6C, "VALUE='14400'" },
	{ 0x6D, "VALUE='19200'" },
	{ 0x6E, "VALUE='28800'" },
	{ 0x6F, "VALUE='38400'" },
	{ 0x70, "VALUE='PAP'" },
	{ 0x71, "VALUE='CHAP'" },
	{ 0x72, "VALUE='ANALOGUE'" },
	{ 0x73, "VALUE='ISDN'" },
	{ 0x74, "VALUE='43200'" },
	{ 0x75, "VALUE='57600'" },
	{ 0x76, "VALUE='MSISDN_NO'" },
	{ 0x77, "VALUE='IPV4'" },
	{ 0x78, "VALUE='MS_CHAP'" },
	{ 0x7C, "TYPE='MMSURL'" },
	{ 0x7D, "TYPE='ID'" },
	{ 0x7E, "NAME='ISP_NAME'" },
	{ 0x7F, "TYPE='BOOKMARK'" },

	{ 0x00, NULL }
};

/*****    Attribute Value tokens   *****/

/***** Token code page aggregation *****/
static const value_valuestring wbxml_nokiaprovc70_tags[] = {
	{ 0, wbxml_nokiaprovc70_tags_cp0 },
	{ 0, NULL }
};

static const value_valuestring wbxml_nokiaprovc70_attrStart[] = {
	{ 0, wbxml_nokiaprovc70_attrStart_cp0 },
	{ 0, NULL }
};






/********************** WBXML token mapping aggregation **********************/


/* The following structure links content types to their token mapping and
 * contains arrays of pointers to value_string arrays (one per code page).
 */
typedef struct _wbxml_token_map {
	const guint32 publicid;  /* WBXML DTD number - see WINA (now OMNA) */
	const gchar *content_type;	/* Content type if no WBXML DTD number */
	const guint8 defined;    /* Are there mapping tables defined */
	const value_valuestring *global;     /* Global token map */
	const value_valuestring *tags;       /* Tag token map */
	const value_valuestring *attrStart;  /* Attribute Start token map */
	const value_valuestring *attrValue;  /* Attribute Value token map */
} wbxml_token_map;

static const wbxml_token_map *wbxml_content_map (guint32 publicid,
		const char *content_type);

/**
 ** Aggregation of content type and aggregated code pages
 ** Content type map lookup will stop at the 1st entry with 3rd member = FALSE
 **/
static const wbxml_token_map map[] = {
#ifdef Test_the_WBXML_parser_without_token_mappings
	{ 0, NULL, FALSE, NULL, NULL, NULL, NULL },
#endif
	{ 0x02, NULL, TRUE, /* WML 1.0 */
		wbxml_wmlc10_global,
		wbxml_wmlc10_tags,
		wbxml_wmlc10_attrStart,
		wbxml_wmlc10_attrValue
	},
#ifdef remove_directive_and_set_TRUE_if_mapping_available
	{ 0x03, NULL, FALSE, /* WTA 1.0 (deprecated) */
		NULL, NULL, NULL, NULL
	},
#endif
	{ 0x04, NULL, TRUE, /* WML 1.1 */
		wbxml_wmlc11_global,
		wbxml_wmlc11_tags,
		wbxml_wmlc11_attrStart,
		wbxml_wmlc11_attrValue
	},
	{ 0x05, NULL, TRUE, /* SI 1.0 */
		NULL, /* wbxml_sic10_global - does not exist */
		wbxml_sic10_tags,
		wbxml_sic10_attrStart,
		wbxml_sic10_attrValue
	},
	{ 0x06, NULL, TRUE, /* SL 1.0 */
		NULL, /* wbxml_slc10_global - does not exist */
		wbxml_slc10_tags,
		wbxml_slc10_attrStart,
		wbxml_slc10_attrValue
	},
	{ 0x07, NULL, TRUE, /* CO 1.0 */
		NULL, /* wbxml_coc10_global - does not exist */
		wbxml_coc10_tags,
		wbxml_coc10_attrStart,
		wbxml_coc10_attrValue
	},
	{ 0x08, NULL, TRUE, /* CHANNEL 1.0 (deprecated) */
		NULL, /* wbxml_channelc10_global - does not exist */
		wbxml_channelc10_tags,
		wbxml_channelc10_attrStart,
		NULL, /* wbxml_channelc10_attrValue - does not exist */
	},
	{ 0x09, NULL, TRUE, /* WML 1.2 */
		wbxml_wmlc12_global,
		wbxml_wmlc12_tags,
		wbxml_wmlc12_attrStart,
		wbxml_wmlc12_attrValue
	},
	{ 0x0A, NULL, TRUE, /* WML 1.3 */
		wbxml_wmlc13_global,
		wbxml_wmlc13_tags,
		wbxml_wmlc13_attrStart,
		wbxml_wmlc13_attrValue
	},
	{ 0x0B, NULL, TRUE, /* PROV 1.0 */
		NULL, /* wbxml_provc10_global - does not exist */
		wbxml_provc10_tags,
		wbxml_provc10_attrStart,
		wbxml_provc10_attrValue
	},
#ifdef remove_directive_and_set_TRUE_if_mapping_available
	{ 0x0C, NULL, FALSE, /* WTA-WML 1.2 */
		NULL, NULL, NULL, NULL
	},
#endif
	{ 0x0D, NULL, TRUE, /* EMN 1.0 */
		NULL, /* wbxml_emnc10_global - does not exist */
		wbxml_emnc10_tags,
		wbxml_emnc10_attrStart,
		wbxml_emnc10_attrValue
	},
#ifdef remove_directive_and_set_TRUE_if_mapping_available
	{ 0x0E, NULL, FALSE, /* DRMREL 1.0 */
		NULL, NULL, NULL, NULL
	},
#endif
	{ 0x020B, NULL, TRUE, /* Nokia OTA Provisioning 7.0 */
		NULL, /* wbxml_nokiaprovc70_global - does not exist */
		wbxml_nokiaprovc70_tags,
		wbxml_nokiaprovc70_attrStart,
		NULL, /* wbxml_nokiaprovc70_attrValue - does not exist */
	},
	{ 0x0FD1, NULL, TRUE, /* SyncML 1.0 */
		NULL, /* wbxml_syncmlc10_global - does not exist */
		wbxml_syncmlc10_tags,
		NULL, /* wbxml_syncmlc10_attrStart - does not exist */
		NULL, /* wbxml_syncmlc10_attrValue - does not exist */
	},
	{ 0x0FD3, NULL, TRUE, /* SyncML 1.1 */
		NULL, /* wbxml_syncmlc11_global - does not exist */
		wbxml_syncmlc11_tags,
		NULL, /* wbxml_syncmlc11_attrStart - does not exist */
		NULL, /* wbxml_syncmlc11_attrValue - does not exist */
	},
	{ 0x1108, NULL, TRUE, /* Phone.com - WML+ 1.1 */
		/* Note: I assumed WML+ 1.1 would be not that different from WML 1.1,
		 *       the real mapping should come from Phone.com (OpenWave)! */
		wbxml_wmlc11_global, /* Not 100% true */
		wbxml_wmlc11_tags, /* Not 100% true */
		wbxml_wmlc11_attrStart, /* Not 100% true */
		wbxml_wmlc11_attrValue /* Not 100% true */
	},
	{ 0x110D, NULL, TRUE, /* Phone.com - WML+ 1.3 */
		/* Note: I assumed WML+ 1.3 would be not that different from WML 1.3,
		 *       the real mapping should come from Phone.com (OpenWave)! */
		wbxml_wmlc13_global, /* Not 100% true */
		wbxml_wmlc13_tags, /* Not 100% true */
		wbxml_wmlc13_attrStart, /* Not 100% true */
		wbxml_wmlc13_attrValue /* Not 100% true */
	},
	
	{ 0, NULL, FALSE, NULL, NULL, NULL, NULL }
};

/* The following map contains entries only registered with a media type */
static const wbxml_token_map textual_map[] = {
	{ 0x00, "application/x-wap-prov.browser-settings", TRUE,
		NULL, /* wbxml_nokiaprovc70_global - does not exist */
		wbxml_nokiaprovc70_tags,
		wbxml_nokiaprovc70_attrStart,
		NULL, /* wbxml_nokiaprovc70_attrValue - does not exist */
	},
	{ 0x00, "application/x-wap-prov.browser-bookmarks", TRUE,
		NULL, /* wbxml_nokiaprovc70_global - does not exist */
		wbxml_nokiaprovc70_tags,
		wbxml_nokiaprovc70_attrStart,
		NULL, /* wbxml_nokiaprovc70_attrValue - does not exist */
	},
	
	{ 0, NULL, FALSE, NULL, NULL, NULL, NULL }
};

/* WBXML content token mapping depends on the following parameters:
 *   - Content type (guint32)
 *   - Token type (global, tags, attrStart, attrValue)
 *   - Code page for tag and attribute
 *
 * This results in the following steps:
 *   1. Retrieve content type mapping
 *   2. If exists, retrieve token type mapping
 *   3. If exists, retrieve required code page
 *   4. If exists, retrieve token mapping
 */

#define wbxml_UNDEFINED_TOKEN \
	"(Requested token not defined for this content type)"
#define wbxml_UNDEFINED_TOKEN_CODE_PAGE \
	"(Requested token code page not defined for this content type)"
#define wbxml_UNDEFINED_TOKEN_MAP \
	"(Requested token map not defined for this content type)"
/* Return token mapping for a given content mapping entry. */
static const char *
map_token (const value_valuestring *token_map, guint8 codepage, guint8 token) {
	const value_string *vs;
	const char *s;

	if (token_map) { /* Found map */
		if ((vs = val_to_valstr (codepage, token_map))) {
			/* Found codepage map */
			s = match_strval (token, vs);
			if (s) { /* Found valid token */
				DebugLog(("map_token(codepage = %u, token = %u: [%s]\n", codepage, token, s));
				return s;
			}
			/* No valid token mapping in specified code page of token map */
			DebugLog(("map_token(codepage = %u, token = %u: "
						wbxml_UNDEFINED_TOKEN "\n", codepage, token));
			return wbxml_UNDEFINED_TOKEN;
		}
		/* There is no token map entry for the requested code page */
		DebugLog(("map_token(codepage = %u, token = %u: "
					wbxml_UNDEFINED_TOKEN_CODE_PAGE "\n", codepage, token));
		return wbxml_UNDEFINED_TOKEN_CODE_PAGE;
	}
	/* The token map does not exist */
	DebugLog(("map_token(codepage = %u, token = %u: "
				wbxml_UNDEFINED_TOKEN_MAP "\n", codepage, token));
	return wbxml_UNDEFINED_TOKEN_MAP;
}


/* Returns a pointer to the WBXML token map for the given WBXML public
 * identifier value (see WINA for a table with defined identifiers). */
static const wbxml_token_map *wbxml_content_map (guint32 publicid,
		const char *content_type) {
	gint i = 0;

	DebugLog(("wbxml_token_map: publicid = %u, content_type = [%s]\n",
				publicid, content_type));
	/* First look whether we have a publicid mapping */
	while (map[i].defined) {
		if (map[i].publicid == publicid)
			return &(map[i]);
		i++;
	}
	/* Then look if the content type has a mapping */
	if (content_type && content_type[0]) {
		DebugLog(("wbxml_token_map(no match for publicid = %u;"
					" looking up content_type = [%s])\n",
					publicid, content_type));
		i = 0;
		while(textual_map[i].defined) {
			if (strcasecmp(content_type, textual_map[i].content_type) == 0) {
				return &(textual_map[i]);
			}
			i++;
		}
	}
	DebugLog(("wbxml_token_map(no match for publicid = %u"
				" or content_type = [%s])\n",
				publicid, content_type));
	return NULL;
}


/************************** Function prototypes **************************/


static void
dissect_wbxml(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

void
proto_register_wbxml(void);

/* Parse and display the WBXML string table */
static void
show_wbxml_string_table (proto_tree *tree, tvbuff_t *tvb, guint32 str_tbl,
		guint32 str_tbl_len);

/* Parse data while in STAG state */
static guint32
parse_wbxml_tag (proto_tree *tree, tvbuff_t *tvb, guint32 offset,
		guint32 str_tbl, guint8 *level, guint8 *codepage_stag, guint8 *codepage_attr);

/* Parse data while in STAG state;
 * interpret tokens as defined by content type */
static guint32
parse_wbxml_tag_defined (proto_tree *tree, tvbuff_t *tvb, guint32 offset,
		guint32 str_tbl, guint8 *level, guint8 *codepage_stag, guint8 *codepage_attr,
		const wbxml_token_map *map);

/* Parse data while in ATTR state */
static guint32
parse_wbxml_attribute_list (proto_tree *tree, tvbuff_t *tvb,
		guint32 offset, guint32 str_tbl, guint8 level, guint8 *codepage_attr);

/* Parse data while in ATTR state;
 * interpret tokens as defined by content type */
static guint32
parse_wbxml_attribute_list_defined (proto_tree *tree, tvbuff_t *tvb,
		guint32 offset, guint32 str_tbl, guint8 level, guint8 *codepage_attr,
		const wbxml_token_map *map);


/****************** WBXML protocol dissection functions ******************/


/* Code to actually dissect the packets */
static void
dissect_wbxml(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	/* Set up structures needed to add the protocol subtree and manage it */
	proto_item *ti;
	proto_tree *wbxml_tree; /* Main WBXML tree */
	proto_tree *wbxml_str_tbl_tree; /* String table subtree */
	proto_tree *wbxml_content_tree; /* Content subtree */
	guint8 version;
	guint offset = 0;
	guint32 len;
	guint32 charset = 0;
	guint32 charset_len = 0;
	guint32 publicid;
	guint32 publicid_index = 0;
	guint32 publicid_len;
	guint32 str_tbl;
	guint32 str_tbl_len;
	guint32 str_tbl_len_len = 0;
	guint8 level = 0; /* WBXML recursion level */
	const wbxml_token_map *content_map = NULL;
	gchar *summary = NULL;
	guint8 codepage_stag = 0;
	guint8 codepage_attr = 0;

	DebugLog(("dissect_wbxml: Dissecting packet %u\n", pinfo->fd->num));
	/* WBXML format
	 * 
	 * Version 1.0: version publicid         strtbl BODY
	 * Version 1.x: version publicid charset strtbl BODY
	 *
	 * Last valid format: WBXML 1.3
	 */
	switch ( version = tvb_get_guint8 (tvb, 0) ) {
		case 0x00: /* WBXML/1.0 */
			break;

		case 0x01: /* WBXML/1.1 */
		case 0x02: /* WBXML/1.2 */
		case 0x03: /* WBXML/1.3 */
			break;

		default:
			return;
	}

	/* In order to properly construct the packet summary,
	 * I need to read the entire WBXML header
	 * up to the string table length.
	 */

	/* Public ID */
	publicid = tvb_get_guintvar(tvb, 1, &publicid_len);
	if (! publicid) {
		/* Public identifier in string table */
		publicid_index = tvb_get_guintvar (tvb, 1+publicid_len, &len);
		publicid_len += len;
	}
	offset = 1 + publicid_len;

	/* Version-specific handling of Charset */
	switch ( version ) {
		case 0x00: /* WBXML/1.0 */
			/* No charset */
			break;

		case 0x01: /* WBXML/1.1 */
		case 0x02: /* WBXML/1.2 */
		case 0x03: /* WBXML/1.3 */
			/* Get charset */
			charset = tvb_get_guintvar (tvb, offset, &charset_len);
			offset += charset_len;
			break;

		default: /* Impossible since we returned already earlier */
			g_error("%s:%u: WBXML version octet 0x%02X only partly supported!\n"
					"Please report this as a bug.\n", __FILE__, __LINE__, version);
			g_assert_not_reached();
			break;
	}

	/* String table: read string table length in bytes */
	str_tbl_len = tvb_get_guintvar (tvb, offset, &str_tbl_len_len);
	str_tbl = offset + str_tbl_len_len; /* Start of 1st string in string table */

	/* Compose the summary line */
	if ( publicid ) {
		summary = g_strdup_printf("%s, Public ID: \"%s\"",
				match_strval (version, vals_wbxml_versions),
				match_strval (publicid, vals_wbxml_public_ids));
	} else {
		/* Read length of Public ID from string table */
		len = tvb_strsize (tvb, str_tbl + publicid_index);
		summary = g_strdup_printf("%s, Public ID: \"%s\"",
				match_strval (version, vals_wbxml_versions),
				tvb_format_text (tvb, str_tbl + publicid_index, len - 1));
	}

	/* Add summary to INFO column if it is enabled */
	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, " (WBXML %s)", summary);

	/* create display subtree for the protocol */
	ti = proto_tree_add_item (tree, proto_wbxml, tvb, 0, -1, FALSE);
	proto_item_append_text(ti, ", Version: %s", summary);
	g_free(summary);
	/*
	 * Now show the protocol subtree, if tree is set.
	 */
	if ( tree ) {
		wbxml_tree = proto_item_add_subtree(ti, ett_wbxml);

		/* WBXML Version */
		proto_tree_add_uint (wbxml_tree, hf_wbxml_version,
				tvb, 0, 1, version);

		/* Public ID */
		if (publicid) { /* Known Public ID */
			proto_tree_add_uint(wbxml_tree, hf_wbxml_public_id_known,
					tvb, 1, publicid_len, publicid);
		} else { /* Public identifier in string table */
			proto_tree_add_item (wbxml_tree, hf_wbxml_public_id_literal,
					tvb, 1, publicid_len, FALSE);
		}
		offset = 1 + publicid_len;

		if ( version ) { /* Charset */
			proto_tree_add_uint (wbxml_tree, hf_wbxml_charset,
					tvb, 1 + publicid_len, charset_len, charset);
			offset += charset_len;
		}

		str_tbl_len = tvb_get_guintvar (tvb, offset, &len);
		str_tbl = offset + len; /* Start of 1st string in string table */

		/* String Table */
		ti = proto_tree_add_text(wbxml_tree,
				tvb, offset, len + str_tbl_len, "String table: %u bytes",
				str_tbl_len);

		if (wbxml_tree && str_tbl_len) { /* Display string table as subtree */
			wbxml_str_tbl_tree = proto_item_add_subtree (ti,
					ett_wbxml_str_tbl);
			show_wbxml_string_table (wbxml_str_tbl_tree, tvb,
					str_tbl, str_tbl_len);
		}

		/* Data starts HERE */
		offset += len + str_tbl_len;

		/* The WBXML BODY starts here */
		ti = proto_tree_add_text (wbxml_tree, tvb, offset, -1,
				"Data representation");
		wbxml_content_tree = proto_item_add_subtree (ti, ett_wbxml_content);

		/* The parse_wbxml_X() functions will process the content correctly,
		 * irrespective of the WBXML version used. For the WBXML body, this
		 * means that there is a different processing for the global token
		 * RESERVED_2 (WBXML 1.0) or OPAQUE (WBXML 1.x with x > 0).  */
		if (wbxml_tree) { /* Show only if visible */
			if (publicid) {
				/* Retrieve the content token mapping if available */
				content_map = wbxml_content_map (publicid, pinfo->match_string);
				if (content_map) {
					/* Is there a defined token mapping for publicid? */
					if (content_map->defined) {
						if (content_map->content_type) {
							proto_item_append_text(ti,
									" is based on Content-Type: %s",
									content_map->content_type);
						}
						proto_tree_add_text (wbxml_content_tree, tvb,
								offset, -1,
								"Level | State | Codepage "
								"| WBXML Token Description         "
								"| Rendering");
						len = parse_wbxml_tag_defined (wbxml_content_tree,
								tvb, offset, str_tbl, &level, &codepage_stag,
								&codepage_attr, content_map);
						return;
					}
				}
				proto_tree_add_text (wbxml_content_tree, tvb,
						offset, -1,
						"[Rendering of this content type"
						" not (yet) supported]");
			}
			/* Default: WBXML only, no interpretation of the content */
			proto_tree_add_text (wbxml_content_tree, tvb, offset, -1,
					"Level | State | Codepage "
					"| WBXML Token Description         "
					"| Rendering");
			len = parse_wbxml_tag (wbxml_content_tree, tvb, offset,
					str_tbl, &level, &codepage_stag, &codepage_attr);
			return;
		}
		return;
	}
}


/* Parse and display the WBXML string table (in a 3-column table format).
 * This function displays:
 *  - the offset in the string table,
 *  - the length of the string
 *  - the string.
 */
static void
show_wbxml_string_table (proto_tree *tree, tvbuff_t *tvb, guint32 str_tbl,
		guint32 str_tbl_len)
{
	guint32 off = str_tbl;
	guint32 len = 0;
	guint32 end = str_tbl + str_tbl_len;

	proto_tree_add_text (tree, tvb, off, end,
			"Start  | Length | String");
	while (off < end) {
		len = tvb_strsize (tvb, off);
		proto_tree_add_text (tree, tvb, off, len,
				"%6d | %6d | '%s'",
				off - str_tbl, len,
				tvb_format_text (tvb, off, len-1));
		off += len;
	}
}


/* Indentation code is based on a static const array of space characters.
 * At least one single space is returned */
static const char indent_buffer[514] = " "
	"                                                                "
	"                                                                "
	"                                                                "
	"                                                                "
	"                                                                "
	"                                                                "
	"                                                                "
	"                                                                "
	; /* Generate XML indentation (length = 1 + 2 * 256 + 1 for '\0') */

static const char * Indent (guint8 level) {
	return indent_buffer + (512 - 2 * (level));
}


/********************
 * WBXML tag tokens *
 ********************
 * 
 * Bit Mask  : Example
 * -------------------
 * 00.. .... : <tag />
 *
 * 01.. .... : <tag>
 *               CONTENT
 *             </tag>
 *
 * 10.. .... : <tag
 *               atrtribute1="value1"
 *               atrtribute2="value2"
 *             />
 * 
 * 11.. .... : <tag
 *               atrtribute1="value1"
 *               atrtribute2="value2"
 *             >
 *               CONTENT
 *             </tag>
 *
 * NOTES
 *   - An XML PI is parsed as an attribute list (same syntax).
 *   - A code page switch only applies to the single token that follows.
 */


/* This function parses the WBXML and maps known token interpretations
 * to the WBXML tokens. As a result, the original XML document can be
 * recreated. Indentation is generated in order to ease reading.
 *
 * Attribute parsing is done in parse_wbxml_attribute_list_defined().
 *
 * The wbxml_token_map entry *map contains the actual token mapping.
 *
 * NOTE: In order to parse the content, some recursion is required.
 *       However, for performance reasons, recursion has been avoided
 *       where possible (tags without content within tags with content).
 *       This is achieved by means of the parsing_tag_content and tag_save*
 *       variables.
 *
 * NOTE: See above for known token mappings.
 *
 * NOTE: As tags can be opened and closed, a tag representation lookup
 *       may happen once or twice for a given tag. For efficiency reasons,
 *       the literal tag value is stored and used throughout the code.
 *       With the introduction of code page support, this solution is robust
 *       as the lookup only occurs once, removing the need for storage of
 *       the used code page.
 */
static guint32
parse_wbxml_tag_defined (proto_tree *tree, tvbuff_t *tvb, guint32 offset,
		guint32 str_tbl, guint8 *level, guint8 *codepage_stag, guint8 *codepage_attr,
		const wbxml_token_map *map)
{
	guint32 tvb_len = tvb_reported_length (tvb);
	guint32 off = offset;
	guint32 len;
	guint str_len;
	guint32 ent;
	guint32 index;
	guint8 peek;
	guint32 tag_len; /* Length of the index (uintvar) from a LITERAL tag */
	guint8 tag_save_known = 0; /* Will contain peek & 0x3F (tag identity) */
	guint8 tag_new_known = 0; /* Will contain peek & 0x3F (tag identity) */
	const char *tag_save_literal; /* Will contain the LITERAL tag identity */
	const char *tag_new_literal; /* Will contain the LITERAL tag identity */
	guint8 parsing_tag_content = FALSE; /* Are we parsing content from a
										   tag with content: <x>Content</x>
										   
										   The initial state is FALSE.
										   This state will trigger recursion. */
	tag_save_literal = NULL; /* Prevents compiler warning */

	DebugLog(("parse_wbxml_tag_defined (level = %u, offset = %u)\n", *level, offset));
	while (off < tvb_len) {
		peek = tvb_get_guint8 (tvb, off);
		DebugLog(("STAG: (top of while) level = %3u, peek = 0x%02X, off = %u, tvb_len = %u\n", *level, peek, off, tvb_len));
		if ((peek & 0x3F) < 4) switch (peek) { /* Global tokens in state = STAG
												  but not the LITERAL tokens */
			case 0x00: /* SWITCH_PAGE */
				*codepage_stag = tvb_get_guint8 (tvb, off+1);
				proto_tree_add_text (tree, tvb, off, 2,
						"      | Tag   | T -->%3d "
						"| SWITCH_PAGE (Tag code page)     "
						"|",
						*codepage_stag);
				off += 2;
				break;
			case 0x01: /* END: only possible for Tag with Content */
				if (tag_save_known) { /* Known TAG */
					proto_tree_add_text (tree, tvb, off, 1,
							"  %3d | Tag   | T %3d    "
							"| END (Known Tag 0x%02X)            "
							"| %s</%s>",
							*level, *codepage_stag,
							tag_save_known, Indent (*level),
							tag_save_literal); /* We already looked it up! */
				} else { /* Literal TAG */
					proto_tree_add_text (tree, tvb, off, 1,
							"  %3d | Tag   | T %3d    "
							"| END (Literal Tag)               "
							"| %s</%s>",
							*level, *codepage_stag, Indent (*level),
							tag_save_literal);
				}
				(*level)--;
				off++;
				/* Reset code page: not needed as return from recursion */
				DebugLog(("STAG: level = %u, Return: len = %u\n", *level, off - offset));
				return (off - offset);
				break;
			case 0x02: /* ENTITY */
				ent = tvb_get_guintvar (tvb, off+1, &len);
				proto_tree_add_text (tree, tvb, off, 1+len,
						"  %3d | Tag   | T %3d    "
						"| ENTITY                          "
						"| %s'&#%u;'",
						*level, *codepage_stag, Indent (*level), ent);
				off += 1+len;
				break;
			case 0x03: /* STR_I */
				len = tvb_strsize (tvb, off+1);
				proto_tree_add_text (tree, tvb, off, 1+len,
						"  %3d | Tag   | T %3d    "
						"| STR_I (Inline string)           "
						"| %s\'%s\'",
						*level, *codepage_stag, Indent(*level),
						tvb_format_text (tvb, off+1, len-1));
				off += 1+len;
				break;
			case 0x40: /* EXT_I_0 */
			case 0x41: /* EXT_I_1 */
			case 0x42: /* EXT_I_2 */
				/* Extension tokens */
				len = tvb_strsize (tvb, off+1);
				proto_tree_add_text (tree, tvb, off, 1+len,
						"  %3d | Tag   | T %3d    "
						"| EXT_I_%1x    (Extension Token)    "
						"| %s(%s: \'%s\')",
						*level, *codepage_stag,
						peek & 0x0f, Indent (*level),
						map_token (map->global, *codepage_stag, peek),
						tvb_format_text (tvb, off+1, len-1));
				off += 1+len;
				break;
			case 0x43: /* PI */
				proto_tree_add_text (tree, tvb, off, 1,
						"  %3d | Tag   | T %3d    "
						"| PI (XML Processing Instruction) "
						"| %s<?xml",
						*level, *codepage_stag, Indent (*level));
				len = parse_wbxml_attribute_list_defined (tree, tvb, off,
						str_tbl, *level, codepage_attr, map);
				/* Check that there is still room in packet */
				off += len;
				if (off >= tvb_len) {
					DebugLog(("STAG: level = %u, ThrowException: len = %u (short frame)\n", *level, off - offset));
					/*
					 * TODO - Do we need to free g_malloc()ed memory?
					 */
					THROW(ReportedBoundsError);
				}
				proto_tree_add_text (tree, tvb, off-1, 1,
						"  %3d | Tag   | T %3d    "
						"| END (PI)                        "
						"| %s?>",
						*level, *codepage_stag, Indent (*level));
				break;
			case 0x80: /* EXT_T_0 */
			case 0x81: /* EXT_T_1 */
			case 0x82: /* EXT_T_2 */
				/* Extension tokens */
				index = tvb_get_guintvar (tvb, off+1, &len);
				str_len = tvb_strsize (tvb, str_tbl+index);
				proto_tree_add_text (tree, tvb, off, 1+len,
						"  %3d | Tag   | T %3d    "
						"| EXT_T_%1x    (Extension Token)    "
						"| %s(%s: \'%s\')",
						*level, *codepage_stag, peek & 0x0f, Indent (*level),
						map_token (map->global, *codepage_stag, peek),
						tvb_format_text (tvb, str_tbl+index, str_len-1));
				off += 1+len;
				break;
			case 0x83: /* STR_T */
				index = tvb_get_guintvar (tvb, off+1, &len);
				str_len = tvb_strsize (tvb, str_tbl+index);
				proto_tree_add_text (tree, tvb, off, 1+len,
						"  %3d | Tag   | T %3d    "
						"| STR_T (Tableref string)         "
						"| %s\'%s\'",
						*level, *codepage_stag, Indent (*level),
						tvb_format_text (tvb, str_tbl+index, str_len-1));
				off += 1+len;
				break;
			case 0xC0: /* EXT_0 */
			case 0xC1: /* EXT_1 */
			case 0xC2: /* EXT_2 */
				/* Extension tokens */
				proto_tree_add_text (tree, tvb, off, 1,
						"  %3d | Tag   | T %3d    "
						"| EXT_%1x      (Extension Token)    "
						"| %s(%s)",
						*level, *codepage_stag, peek & 0x0f, Indent (*level),
						map_token (map->global, *codepage_stag, peek));
				off++;
				break;
			case 0xC3: /* OPAQUE - WBXML 1.1 and newer */
				if (tvb_get_guint8 (tvb, 0)) { /* WBXML 1.x (x > 0) */
					index = tvb_get_guintvar (tvb, off+1, &len);
					proto_tree_add_text (tree, tvb, off, 1 + len + index,
							"  %3d | Tag   | T %3d    "
							"| OPAQUE (Opaque data)            "
							"| %s(%d bytes of opaque data)",
							*level, *codepage_stag, Indent (*level), index);
					off += 1+len+index;
				} else { /* WBXML 1.0 - RESERVED_2 token (invalid) */
					proto_tree_add_text (tree, tvb, off, 1,
							"  %3d | Tag   | T %3d    "
							"| RESERVED_2     (Invalid Token!) "
							"| WBXML 1.0 parsing stops here.",
							*level, *codepage_stag);
					/* Stop processing as it is impossible to parse now */
					off = tvb_len;
					DebugLog(("STAG: level = %u, Return: len = %u\n", *level, off - offset));
					return (off - offset);
				}
				break;

				/* No default clause, as all cases have been treated */
		} else { /* LITERAL or Known TAG */
			/* We must store the initial tag, and also retrieve the new tag.
			 * For efficiency reasons, we store the literal tag representation
			 * for known tags too, so we can easily close the tag without the
			 * need of a new lookup and avoiding storage of token codepage.
			 * 
			 * There are 4 possibilities:
			 *
			 *  1. Known tag followed by a known tag
			 *  2. Known tag followed by a LITERAL tag
			 *  3. LITERAL tag followed by Known tag
			 *  4. LITERAL tag followed by LITERAL tag
			 */

			/* Store the new tag */
			tag_len = 0;
			if ((peek & 0x3F) == 4) { /* LITERAL */
				DebugLog(("STAG: LITERAL tag (peek = 0x%02X, off = %u) - TableRef follows!\n", peek, off));
				index = tvb_get_guintvar (tvb, off+1, &tag_len);
				str_len = tvb_strsize (tvb, str_tbl+index);
				tag_new_literal = tvb_get_ptr (tvb, str_tbl+index, str_len);
				tag_new_known = 0; /* invalidate known tag_new */
			} else { /* Known tag */
				tag_new_known = peek & 0x3F;
				tag_new_literal = map_token (map->tags, *codepage_stag,
										tag_new_known);
				/* Stored looked up tag name string */
			}

			/* Parsing of TAG starts HERE */
			if (peek & 0x40) { /* Content present */
				/* Content follows
				 * [!] An explicit END token is expected in these cases!
				 * ==> Recursion possible if we encounter a tag with content;
				 *     recursion will return at the explicit END token.
				 */
				if (parsing_tag_content) { /* Recurse */
					DebugLog(("STAG: Tag in Tag - RECURSE! (off = %u)\n", off));
					/* Do not process the attribute list:
					 * recursion will take care of it */
					(*level)++;
					len = parse_wbxml_tag_defined (tree, tvb, off, str_tbl,
							level, codepage_stag, codepage_attr, map);
					off += len;
				} else { /* Now we will have content to parse */
					/* Save the start tag so we can properly close it later. */
					if ((peek & 0x3F) == 4) { /* Literal tag */
						tag_save_literal = tag_new_literal;
						tag_save_known = 0;
					} else { /* Known tag */
						tag_save_known = tag_new_known;
						tag_save_literal = tag_new_literal;
						/* The last statement avoids needless lookups */
					}
					/* Process the attribute list if present */
					if (peek & 0x80) { /* Content and Attribute list present */
						if (tag_new_known) { /* Known tag */
							proto_tree_add_text (tree, tvb, off, 1,
									"  %3d | Tag   | T %3d    "
									"|   Known Tag 0x%02X           (AC) "
									"| %s<%s",
									*level, *codepage_stag, tag_new_known,
									Indent (*level), tag_new_literal);
							/* Tag string already looked up earlier! */
							off++;
						} else { /* LITERAL tag */
							proto_tree_add_text (tree, tvb, off, 1,
									"  %3d | Tag   | T %3d    "
									"| LITERAL_AC (Literal tag)   (AC) "
									"| %s<%s",
									*level, *codepage_stag, Indent (*level), tag_new_literal);
							off += 1 + tag_len;
						}
						len = parse_wbxml_attribute_list_defined (tree, tvb,
								off, str_tbl, *level, codepage_attr, map);
						/* Check that there is still room in packet */
						off += len;
						if (off >= tvb_len) {
							DebugLog(("STAG: level = %u, ThrowException: len = %u (short frame)\n",
										*level, off - offset));
							/*
							 * TODO - Do we need to free g_malloc()ed memory?
							 */
							THROW(ReportedBoundsError);
						}
						proto_tree_add_text (tree, tvb, off-1, 1,
								"  %3d | Tag   | T %3d    "
								"| END (attribute list)            "
								"| %s>",
								*level, *codepage_stag, Indent (*level));
					} else { /* Content, no Attribute list */
						if (tag_new_known) { /* Known tag */
							proto_tree_add_text (tree, tvb, off, 1,
									"  %3d | Tag   | T %3d    "
									"|   Known Tag 0x%02X           (.C) "
									"| %s<%s>",
									*level, *codepage_stag, tag_new_known,
									Indent (*level), tag_new_literal);
							/* Tag string already looked up earlier! */
							off++;
						} else { /* LITERAL tag */
							proto_tree_add_text (tree, tvb, off, 1,
									"  %3d | Tag   | T %3d    "
									"| LITERAL_C  (Literal Tag)   (.C) "
									"| %s<%s>",
									*level, *codepage_stag, Indent (*level),
									tag_new_literal);
							off += 1 + tag_len;
						}
					}
					/* The data that follows in the parsing process
					 * represents content for the opening tag
					 * we've just processed in the lines above.
					 * Next time we encounter a tag with content: recurse
					 */
					parsing_tag_content = TRUE;
					DebugLog(("Tag in Tag - No recursion this time! (off = %u)\n", off));
				}
			} else { /* No Content */
				DebugLog(("<Tag/> in Tag - No recursion! (off = %u)\n", off));
				(*level)++;
				if (peek & 0x80) { /* No Content, Attribute list present */
					if (tag_new_known) { /* Known tag */
						proto_tree_add_text (tree, tvb, off, 1,
								"  %3d | Tag   | T %3d    "
								"|   Known Tag 0x%02X           (A.) "
								"| %s<%s",
								*level, *codepage_stag, tag_new_known,
								Indent (*level), tag_new_literal);
						/* Tag string already looked up earlier! */
						off++;
						len = parse_wbxml_attribute_list_defined (tree, tvb,
								off, str_tbl, *level, codepage_attr, map);
						/* Check that there is still room in packet */
						off += len;
						if (off >= tvb_len) {
							DebugLog(("STAG: level = %u, ThrowException: len = %u (short frame)\n", *level, off - offset));
							/*
							 * TODO - Do we need to free g_malloc()ed memory?
							 */
							THROW(ReportedBoundsError);
						}
						proto_tree_add_text (tree, tvb, off-1, 1,
								"  %3d | Tag   | T %3d    "
								"| END (Known Tag)                 "
								"| %s/>",
								*level, *codepage_stag, Indent (*level));
					} else { /* LITERAL tag */
						proto_tree_add_text (tree, tvb, off, 1,
								"  %3d | Tag   | T %3d    "
								"| LITERAL_A  (Literal Tag)   (A.) "
								"| %s<%s",
								*level, *codepage_stag, Indent (*level), tag_new_literal);
						off += 1 + tag_len;
						len = parse_wbxml_attribute_list_defined (tree, tvb,
								off, str_tbl, *level, codepage_attr, map);
						/* Check that there is still room in packet */
						off += len;
						if (off >= tvb_len) {
							DebugLog(("STAG: level = %u, ThrowException: len = %u (short frame)\n", *level, off - offset));
							/*
							 * TODO - Do we need to free g_malloc()ed memory?
							 */
							THROW(ReportedBoundsError);
						}
						proto_tree_add_text (tree, tvb, off-1, 1,
								"  %3d | Tag   | T %3d    "
								"| END (Literal Tag)               "
								"| %s/>",
								*level, *codepage_stag, Indent (*level));
					}
				} else { /* No Content, No Attribute list */
					if (tag_new_known) { /* Known tag */
						proto_tree_add_text (tree, tvb, off, 1,
								"  %3d | Tag   | T %3d    "
								"|   Known Tag 0x%02x           (..) "
								"| %s<%s />",
								*level, *codepage_stag, tag_new_known,
								Indent (*level), tag_new_literal);
						/* Tag string already looked up earlier! */
						off++;
					} else { /* LITERAL tag */
						proto_tree_add_text (tree, tvb, off, 1,
								"  %3d | Tag   | T %3d    "
								"| LITERAL    (Literal Tag)   (..) "
								"| %s<%s />",
								*level, *codepage_stag, Indent (*level),
								tag_new_literal);
						off += 1 + tag_len;
					}
				}
				(*level)--;
				/* TODO: Do I have to reset code page here? */
			}
		} /* if (tag & 0x3F) >= 5 */
	} /* while */
	DebugLog(("STAG: level = %u, Return: len = %u (end of function body)\n", *level, off - offset));
	return (off - offset);
}


/* This function performs the WBXML decoding as in parse_wbxml_tag_defined()
 * but this time no WBXML mapping is performed.
 *
 * Attribute parsing is done in parse_wbxml_attribute_list().
 */
static guint32
parse_wbxml_tag (proto_tree *tree, tvbuff_t *tvb, guint32 offset,
		guint32 str_tbl, guint8 *level,
		guint8 *codepage_stag, guint8 *codepage_attr)
{
	guint32 tvb_len = tvb_reported_length (tvb);
	guint32 off = offset;
	guint32 len;
	guint str_len;
	guint32 ent;
	guint32 index;
	guint8 peek;
	guint32 tag_len; /* Length of the index (uintvar) from a LITERAL tag */
	guint8 tag_save_known = 0; /* Will contain peek & 0x3F (tag identity) */
	guint8 tag_new_known = 0; /* Will contain peek & 0x3F (tag identity) */
	const char *tag_save_literal; /* Will contain the LITERAL tag identity */
	const char *tag_new_literal; /* Will contain the LITERAL tag identity */
	char tag_save_buf[10]; /* Will contain "tag_0x%02X" */
	char tag_new_buf[10]; /* Will contain "tag_0x%02X" */
	guint8 parsing_tag_content = FALSE; /* Are we parsing content from a
										   tag with content: <x>Content</x>
										   
										   The initial state is FALSE.
										   This state will trigger recursion. */
	tag_save_literal = NULL; /* Prevents compiler warning */

	DebugLog(("parse_wbxml_tag (level = %u, offset = %u)\n", *level, offset));
	while (off < tvb_len) {
		peek = tvb_get_guint8 (tvb, off);
		DebugLog(("STAG: (top of while) level = %3u, peek = 0x%02X, off = %u, tvb_len = %u\n", *level, peek, off, tvb_len));
		if ((peek & 0x3F) < 4) switch (peek) { /* Global tokens in state = STAG
												  but not the LITERAL tokens */
			case 0x00: /* SWITCH_PAGE */
				*codepage_stag = tvb_get_guint8 (tvb, off+1);
				proto_tree_add_text (tree, tvb, off, 2,
						"      | Tag   | T -->%3d "
						"| SWITCH_PAGE (Tag code page)     "
						"|",
						*codepage_stag);
				off += 2;
				break;
			case 0x01: /* END: only possible for Tag with Content */
				if (tag_save_known) { /* Known TAG */
					proto_tree_add_text (tree, tvb, off, 1,
							"  %3d | Tag   | T %3d    "
							"| END (Known Tag 0x%02X)            "
							"| %s</%s>",
							*level, *codepage_stag, tag_save_known,
							Indent (*level),
							tag_save_literal); /* We already looked it up! */
				} else { /* Literal TAG */
					proto_tree_add_text (tree, tvb, off, 1,
							"  %3d | Tag   | T %3d    "
							"| END (Literal Tag)               "
							"| %s</%s>",
							*level, *codepage_stag, Indent (*level),
							tag_save_literal);
				}
				(*level)--;
				off++;
				/* Reset code page: not needed as return from recursion */
				DebugLog(("STAG: level = %u, Return: len = %u\n",
							*level, off - offset));
				return (off - offset);
				break;
			case 0x02: /* ENTITY */
				ent = tvb_get_guintvar (tvb, off+1, &len);
				proto_tree_add_text (tree, tvb, off, 1+len,
						"  %3d | Tag   | T %3d    "
						"| ENTITY                          "
						"| %s'&#%u;'",
						*level, *codepage_stag, Indent (*level), ent);
				off += 1+len;
				break;
			case 0x03: /* STR_I */
				len = tvb_strsize (tvb, off+1);
				proto_tree_add_text (tree, tvb, off, 1+len,
						"  %3d | Tag   | T %3d    "
						"| STR_I (Inline string)           "
						"| %s\'%s\'",
						*level, *codepage_stag, Indent(*level),
						tvb_format_text (tvb, off+1, len-1));
				off += 1+len;
				break;
			case 0x40: /* EXT_I_0 */
			case 0x41: /* EXT_I_1 */
			case 0x42: /* EXT_I_2 */
				/* Extension tokens */
				len = tvb_strsize (tvb, off+1);
				proto_tree_add_text (tree, tvb, off, 1+len,
						"  %3d | Tag   | T %3d    "
						"| EXT_I_%1x    (Extension Token)    "
						"| %s(Inline string extension: \'%s\')",
						*level, *codepage_stag, peek & 0x0f, Indent (*level),
						tvb_format_text (tvb, off+1, len-1));
				off += 1+len;
				break;
			case 0x43: /* PI */
				proto_tree_add_text (tree, tvb, off, 1,
						"  %3d | Tag   | T %3d    "
						"| PI (XML Processing Instruction) "
						"| %s<?xml",
						*level, *codepage_stag, Indent (*level));
				len = parse_wbxml_attribute_list (tree, tvb, off, str_tbl,
						*level, codepage_attr);
				/* Check that there is still room in packet */
				off += len;
				if (off >= tvb_len) {
					DebugLog(("STAG: level = %u, ThrowException: len = %u (short frame)\n",
								*level, off - offset));
					/*
					 * TODO - Do we need to free g_malloc()ed memory?
					 */
					THROW(ReportedBoundsError);
				}
				proto_tree_add_text (tree, tvb, off-1, 1,
						"  %3d | Tag   | T %3d    "
						"| END (PI)                        "
						"| %s?>",
						*level, *codepage_stag, Indent (*level));
				break;
			case 0x80: /* EXT_T_0 */
			case 0x81: /* EXT_T_1 */
			case 0x82: /* EXT_T_2 */
				/* Extension tokens */
				index = tvb_get_guintvar (tvb, off+1, &len);
				str_len = tvb_strsize (tvb, str_tbl+index);
				proto_tree_add_text (tree, tvb, off, 1+len,
						"  %3d | Tag   | T %3d    "
						"| EXT_T_%1x    (Extension Token)    "
						"| %s(Tableref string extension: \'%s\')",
						*level, *codepage_stag, peek & 0x0f, Indent (*level),
						tvb_format_text (tvb, str_tbl+index, str_len-1));
				off += 1+len;
				break;
			case 0x83: /* STR_T */
				index = tvb_get_guintvar (tvb, off+1, &len);
				str_len = tvb_strsize (tvb, str_tbl+index);
				proto_tree_add_text (tree, tvb, off, 1+len,
						"  %3d | Tag   | T %3d    "
						"| STR_T (Tableref string)         "
						"| %s\'%s\'",
						*level, *codepage_stag, Indent (*level),
						tvb_format_text (tvb, str_tbl+index, str_len-1));
				off += 1+len;
				break;
			case 0xC0: /* EXT_0 */
			case 0xC1: /* EXT_1 */
			case 0xC2: /* EXT_2 */
				/* Extension tokens */
				proto_tree_add_text (tree, tvb, off, 1,
						"  %3d | Tag   | T %3d    "
						"| EXT_%1x      (Extension Token)    "
						"| %s(Single-byte extension)",
						*level, *codepage_stag, peek & 0x0f, Indent (*level));
				off++;
				break;
			case 0xC3: /* OPAQUE - WBXML 1.1 and newer */
				if (tvb_get_guint8 (tvb, 0)) { /* WBXML 1.x (x > 0) */
					index = tvb_get_guintvar (tvb, off+1, &len);
					proto_tree_add_text (tree, tvb, off, 1 + len + index,
							"  %3d | Tag   | T %3d    "
							"| OPAQUE (Opaque data)            "
							"| %s(%d bytes of opaque data)",
							*level, *codepage_stag, Indent (*level), index);
					off += 1+len+index;
				} else { /* WBXML 1.0 - RESERVED_2 token (invalid) */
					proto_tree_add_text (tree, tvb, off, 1,
							"  %3d | Tag   | T %3d    "
							"| RESERVED_2     (Invalid Token!) "
							"| WBXML 1.0 parsing stops here.",
							*level, *codepage_stag);
					/* Stop processing as it is impossible to parse now */
					off = tvb_len;
					DebugLog(("STAG: level = %u, Return: len = %u\n",
								*level, off - offset));
					return (off - offset);
				}
				break;

				/* No default clause, as all cases have been treated */
		} else { /* LITERAL or Known TAG */
			/* We must store the initial tag, and also retrieve the new tag.
			 * For efficiency reasons, we store the literal tag representation
			 * for known tags too, so we can easily close the tag without the
			 * need of a new lookup and avoiding storage of token codepage.
			 * 
			 * There are 4 possibilities:
			 *
			 *  1. Known tag followed by a known tag
			 *  2. Known tag followed by a LITERAL tag
			 *  3. LITERAL tag followed by Known tag
			 *  4. LITERAL tag followed by LITERAL tag
			 */

			/* Store the new tag */
			tag_len = 0;
			if ((peek & 0x3F) == 4) { /* LITERAL */
				DebugLog(("STAG: LITERAL tag (peek = 0x%02X, off = %u)"
							" - TableRef follows!\n", peek, off));
				index = tvb_get_guintvar (tvb, off+1, &tag_len);
				str_len = tvb_strsize (tvb, str_tbl+index);
				tag_new_literal = tvb_get_ptr (tvb, str_tbl+index, str_len);
				tag_new_known = 0; /* invalidate known tag_new */
			} else { /* Known tag */
				tag_new_known = peek & 0x3F;
				sprintf (tag_new_buf, "Tag_0x%02X",
						tag_new_known);
				tag_new_literal = tag_new_buf;
				/* Stored looked up tag name string */
			}

			/* Parsing of TAG starts HERE */
			if (peek & 0x40) { /* Content present */
				/* Content follows
				 * [!] An explicit END token is expected in these cases!
				 * ==> Recursion possible if we encounter a tag with content;
				 *     recursion will return at the explicit END token.
				 */
				if (parsing_tag_content) { /* Recurse */
					DebugLog(("STAG: Tag in Tag - RECURSE! (off = %u)\n", off));
					/* Do not process the attribute list:
					 * recursion will take care of it */
					(*level)++;
					len = parse_wbxml_tag (tree, tvb, off, str_tbl, level,
							codepage_stag, codepage_attr);
					off += len;
				} else { /* Now we will have content to parse */
					/* Save the start tag so we can properly close it later. */
					if ((peek & 0x3F) == 4) { /* Literal tag */
						tag_save_literal = tag_new_literal;
						tag_save_known = 0;
					} else { /* Known tag */
						tag_save_known = tag_new_known;
						sprintf (tag_save_buf, "Tag_0x%02X",
								tag_new_known);
						tag_save_literal = tag_save_buf;
						/* The last statement avoids needless lookups */
					}
					/* Process the attribute list if present */
					if (peek & 0x80) { /* Content and Attribute list present */
						if (tag_new_known) { /* Known tag */
							proto_tree_add_text (tree, tvb, off, 1,
									"  %3d | Tag   | T %3d    "
									"|   Known Tag 0x%02X           (AC) "
									"| %s<%s",
									*level, *codepage_stag, tag_new_known,
									Indent (*level), tag_new_literal);
							/* Tag string already looked up earlier! */
							off++;
						} else { /* LITERAL tag */
							proto_tree_add_text (tree, tvb, off, 1,
									"  %3d | Tag   | T %3d    "
									"| LITERAL_AC (Literal tag)   (AC) "
									"| %s<%s",
									*level, *codepage_stag, Indent (*level),
									tag_new_literal);
							off += 1 + tag_len;
						}
						len = parse_wbxml_attribute_list (tree, tvb,
								off, str_tbl, *level, codepage_attr);
						/* Check that there is still room in packet */
						off += len;
						if (off >= tvb_len) {
							DebugLog(("STAG: level = %u, ThrowException: "
										"len = %u (short frame)\n",
										*level, off - offset));
							/*
							 * TODO - Do we need to free g_malloc()ed memory?
							 */
							THROW(ReportedBoundsError);
						}
						proto_tree_add_text (tree, tvb, off-1, 1,
								"  %3d | Tag   | T %3d    "
								"| END (attribute list)            "
								"| %s>",
								*level, *codepage_stag, Indent (*level));
					} else { /* Content, no Attribute list */
						if (tag_new_known) { /* Known tag */
							proto_tree_add_text (tree, tvb, off, 1,
									"  %3d | Tag   | T %3d    "
									"|   Known Tag 0x%02X           (.C) "
									"| %s<%s>",
									*level, *codepage_stag, tag_new_known,
									Indent (*level), tag_new_literal);
							/* Tag string already looked up earlier! */
							off++;
						} else { /* LITERAL tag */
							proto_tree_add_text (tree, tvb, off, 1,
									"  %3d | Tag   | T %3d    "
									"| LITERAL_C  (Literal Tag)   (.C) "
									"| %s<%s>",
									*level, *codepage_stag, Indent (*level),
									tag_new_literal);
							off += 1 + tag_len;
						}
					}
					/* The data that follows in the parsing process
					 * represents content for the opening tag
					 * we've just processed in the lines above.
					 * Next time we encounter a tag with content: recurse
					 */
					parsing_tag_content = TRUE;
					DebugLog(("Tag in Tag - No recursion this time! "
								"(off = %u)\n", off));
				}
			} else { /* No Content */
				DebugLog(("<Tag/> in Tag - No recursion! (off = %u)\n", off));
				(*level)++;
				if (peek & 0x80) { /* No Content, Attribute list present */
					if (tag_new_known) { /* Known tag */
						proto_tree_add_text (tree, tvb, off, 1,
								"  %3d | Tag   | T %3d    "
								"|   Known Tag 0x%02X           (A.) "
								"| %s<%s",
								*level, *codepage_stag, tag_new_known,
								Indent (*level), tag_new_literal);
						/* Tag string already looked up earlier! */
						off++;
						len = parse_wbxml_attribute_list (tree, tvb,
								off, str_tbl, *level, codepage_attr);
						/* Check that there is still room in packet */
						off += len;
						if (off >= tvb_len) {
							DebugLog(("STAG: level = %u, ThrowException: "
										"len = %u (short frame)\n",
										*level, off - offset));
							/*
							 * TODO - Do we need to free g_malloc()ed memory?
							 */
							THROW(ReportedBoundsError);
						}
						proto_tree_add_text (tree, tvb, off-1, 1,
								"  %3d | Tag   | T %3d    "
								"| END (Known Tag)                 "
								"| %s/>",
								*level, *codepage_stag, Indent (*level));
					} else { /* LITERAL tag */
						proto_tree_add_text (tree, tvb, off, 1,
								"  %3d | Tag   | T %3d    "
								"| LITERAL_A  (Literal Tag)   (A.) "
								"| %s<%s",
								*level, *codepage_stag, Indent (*level),
								tag_new_literal);
						off += 1 + tag_len;
						len = parse_wbxml_attribute_list (tree, tvb,
								off, str_tbl, *level, codepage_attr);
						/* Check that there is still room in packet */
						off += len;
						if (off >= tvb_len) {
							DebugLog(("STAG: level = %u, ThrowException: "
										"len = %u (short frame)\n",
										*level, off - offset));
							/*
							 * TODO - Do we need to free g_malloc()ed memory?
							 */
							THROW(ReportedBoundsError);
						}
						proto_tree_add_text (tree, tvb, off-1, 1,
								"  %3d | Tag   | T %3d    "
								"| END (Literal Tag)               "
								"| %s/>",
								*level, *codepage_stag, Indent (*level));
					}
				} else { /* No Content, No Attribute list */
					if (tag_new_known) { /* Known tag */
						proto_tree_add_text (tree, tvb, off, 1,
								"  %3d | Tag   | T %3d    "
								"|   Known Tag 0x%02x           (..) "
								"| %s<%s />",
								*level, *codepage_stag, tag_new_known,
								Indent (*level), tag_new_literal);
						/* Tag string already looked up earlier! */
						off++;
					} else { /* LITERAL tag */
						proto_tree_add_text (tree, tvb, off, 1,
								"  %3d | Tag   | T %3d    "
								"| LITERAL    (Literal Tag)   (..) "
								"| %s<%s />",
								*level, *codepage_stag, Indent (*level),
								tag_new_literal);
						off += 1 + tag_len;
					}
				}
				(*level)--;
				/* TODO: Do I have to reset code page here? */
			}
		} /* if (tag & 0x3F) >= 5 */
	} /* while */
	DebugLog(("STAG: level = %u, Return: len = %u (end of function body)\n",
				*level, off - offset));
	return (off - offset);
}


/**************************
 * WBXML Attribute tokens *
 **************************
 * Bit Mask  : Example
 * -------------------
 * 0... .... : attr=             (attribute name)
 *             href='http://'    (attribute name with start of attribute value)
 * 1... .... : 'www.'            (attribute value, or part of it)
 * 
 */


/* This function parses the WBXML and maps known token interpretations
 * to the WBXML tokens. As a result, the original XML document can be
 * recreated. Indentation is generated in order to ease reading.
 *
 * This function performs attribute list parsing.
 * 
 * The wbxml_token_map entry *map contains the actual token mapping.
 *
 * NOTE: See above for known token mappings.
 */
static guint32
parse_wbxml_attribute_list_defined (proto_tree *tree, tvbuff_t *tvb,
		guint32 offset, guint32 str_tbl, guint8 level, guint8 *codepage_attr,
		const wbxml_token_map *map)
{
	guint32 tvb_len = tvb_reported_length (tvb);
	guint32 off = offset;
	guint32 len;
	guint str_len;
	guint32 ent;
	guint32 index;
	guint8 peek;

	DebugLog(("parse_wbxml_attr_defined (level = %u, offset = %u)\n",
				level, offset));
	/* Parse attributes */
	while (off < tvb_len) {
		peek = tvb_get_guint8 (tvb, off);
		DebugLog(("ATTR: (top of while) level = %3u, peek = 0x%02X, "
					"off = %u, tvb_len = %u\n", level, peek, off, tvb_len));
		if ((peek & 0x3F) < 5) switch (peek) { /* Global tokens
												  in state = ATTR */
			case 0x00: /* SWITCH_PAGE */
				*codepage_attr = tvb_get_guint8 (tvb, off+1);
				proto_tree_add_text (tree, tvb, off, 2,
						"      |  Attr | A -->%3d "
						"| SWITCH_PAGE (Attr code page)    |",
						*codepage_attr);
				off += 2;
				break;
			case 0x01: /* END */
				/* BEWARE
				 *   The Attribute END token means either ">" or "/>"
				 *   and as a consequence both must be treated separately.
				 *   This is done in the TAG state parser.
				 */
				off++;
				DebugLog(("ATTR: level = %u, Return: len = %u\n",
							level, off - offset));
				return (off - offset);
			case 0x02: /* ENTITY */
				ent = tvb_get_guintvar (tvb, off+1, &len);
				proto_tree_add_text (tree, tvb, off, 1+len,
						"  %3d |  Attr | A %3d    "
						"| ENTITY                          "
						"|     %s'&#%u;'",
						level, *codepage_attr, Indent (level), ent);
				off += 1+len;
				break;
			case 0x03: /* STR_I */
				len = tvb_strsize (tvb, off+1);
				proto_tree_add_text (tree, tvb, off, 1+len,
						"  %3d |  Attr | A %3d    "
						"| STR_I (Inline string)           "
						"|     %s\'%s\'",
						level, *codepage_attr, Indent (level),
						tvb_format_text (tvb, off+1, len-1));
				off += 1+len;
				break;
			case 0x04: /* LITERAL */
				index = tvb_get_guintvar (tvb, off+1, &len);
				str_len = tvb_strsize (tvb, str_tbl+index);
				proto_tree_add_text (tree, tvb, off, 1+len,
						"  %3d |  Attr | A %3d    "
						"| LITERAL (Literal Attribute)     "
						"|   %s<%s />",
						level, *codepage_attr, Indent (level),
						tvb_format_text (tvb, str_tbl+index, str_len-1));
				off += 1+len;
				break;
			case 0x40: /* EXT_I_0 */
			case 0x41: /* EXT_I_1 */
			case 0x42: /* EXT_I_2 */
				/* Extension tokens */
				len = tvb_strsize (tvb, off+1);
				proto_tree_add_text (tree, tvb, off, 1+len,
						"  %3d |  Attr | A %3d    "
						"| EXT_I_%1x    (Extension Token)    "
						"|     %s(%s: \'%s\')",
						level, *codepage_attr, peek & 0x0f, Indent (level),
						map_token (map->global, *codepage_attr, peek),
						tvb_format_text (tvb, off+1, len-1));
				off += 1+len;
				break;
			/* 0x43 impossible in ATTR state */
			/* 0x44 impossible in ATTR state */
			case 0x80: /* EXT_T_0 */
			case 0x81: /* EXT_T_1 */
			case 0x82: /* EXT_T_2 */
				/* Extension tokens */
				index = tvb_get_guintvar (tvb, off+1, &len);
				str_len = tvb_strsize (tvb, str_tbl+index);
				proto_tree_add_text (tree, tvb, off, 1+len,
						"  %3d |  Attr | A %3d    "
						"| EXT_T_%1x    (Extension Token)    "
						"|     %s(%s: \'%s\')",
						level, *codepage_attr, peek & 0x0f, Indent (level),
						map_token (map->global, *codepage_attr, peek),
						tvb_format_text (tvb, str_tbl+index, str_len-1));
				off += 1+len;
				break;
			case 0x83: /* STR_T */
				index = tvb_get_guintvar (tvb, off+1, &len);
				str_len = tvb_strsize (tvb, str_tbl+index);
				proto_tree_add_text (tree, tvb, off, 1+len,
						"  %3d |  Attr | A %3d    "
						"| STR_T (Tableref string)         "
						"|     %s\'%s\'",
						level, *codepage_attr, Indent (level),
						tvb_format_text (tvb, str_tbl+index, str_len-1));
				off += 1+len;
				break;
			/* 0x84 impossible in ATTR state */
			case 0xC0: /* EXT_0 */
			case 0xC1: /* EXT_1 */
			case 0xC2: /* EXT_2 */
				/* Extension tokens */
				proto_tree_add_text (tree, tvb, off, 1,
						"  %3d |  Attr | A %3d    "
						"| EXT_%1x      (Extension Token)    "
						"|     %s(%s)",
						level, *codepage_attr, peek & 0x0f, Indent (level),
						map_token (map->global, *codepage_attr, peek));
				off++;
				break;
			case 0xC3: /* OPAQUE - WBXML 1.1 and newer */
				if (tvb_get_guint8 (tvb, 0)) { /* WBXML 1.x (x > 0) */
					index = tvb_get_guintvar (tvb, off+1, &len);
					proto_tree_add_text (tree, tvb, off, 1 + len + index,
							"  %3d |  Attr | A %3d    "
							"| OPAQUE (Opaque data)            "
							"|       %s(%d bytes of opaque data)",
							level, *codepage_attr, Indent (level), index);
					off += 1+len+index;
				} else { /* WBXML 1.0 - RESERVED_2 token (invalid) */
					proto_tree_add_text (tree, tvb, off, 1,
							"  %3d |  Attr | A %3d    "
							"| RESERVED_2     (Invalid Token!) "
							"| WBXML 1.0 parsing stops here.",
							level, *codepage_attr);
					/* Stop processing as it is impossible to parse now */
					off = tvb_len;
					DebugLog(("ATTR: level = %u, Return: len = %u\n",
								level, off - offset));
					return (off - offset);
				}
				break;
			/* 0xC4 impossible in ATTR state */
			default:
				proto_tree_add_text (tree, tvb, off, 1,
						"  %3d |  Attr | A %3d    "
						"| %-10s     (Invalid Token!) "
						"| WBXML parsing stops here.",
						level, *codepage_attr,
						match_strval (peek, vals_wbxml1x_global_tokens));
				/* Move to end of buffer */
				off = tvb_len;
				break;
		} else { /* Known atribute token */
			if (peek & 0x80) { /* attrValue */
				proto_tree_add_text (tree, tvb, off, 1,
						"  %3d |  Attr | A %3d    "
						"|   Known attrValue 0x%02X          "
						"|       %s%s",
						level, *codepage_attr, peek & 0x7f, Indent (level),
						map_token (map->attrValue, *codepage_attr, peek));
				off++;
			} else { /* attrStart */
				proto_tree_add_text (tree, tvb, off, 1,
						"  %3d |  Attr | A %3d    "
						"|   Known attrStart 0x%02X          "
						"|   %s%s",
						level, *codepage_attr, peek & 0x7f, Indent (level),
						map_token (map->attrStart, *codepage_attr, peek));
				off++;
			}
		}
	} /* End WHILE */
	DebugLog(("ATTR: level = %u, Return: len = %u (end of function body)\n",
				level, off - offset));
	return (off - offset);
}


/* This function performs the WBXML attribute decoding as in
 * parse_wbxml_attribute_list_defined() but this time no WBXML mapping
 * is performed.
 *
 * This function performs attribute list parsing.
 * 
 * NOTE: Code page switches not yet processed in the code!
 */
static guint32
parse_wbxml_attribute_list (proto_tree *tree, tvbuff_t *tvb,
		guint32 offset, guint32 str_tbl, guint8 level, guint8 *codepage_attr)
{
	guint32 tvb_len = tvb_reported_length (tvb);
	guint32 off = offset;
	guint32 len;
	guint str_len;
	guint32 ent;
	guint32 index;
	guint8 peek;

	DebugLog(("parse_wbxml_attr (level = %u, offset = %u)\n", level, offset));
	/* Parse attributes */
	while (off < tvb_len) {
		peek = tvb_get_guint8 (tvb, off);
		DebugLog(("ATTR: (top of while) level = %3u, peek = 0x%02X, "
					"off = %u, tvb_len = %u\n", level, peek, off, tvb_len));
		if ((peek & 0x3F) < 5) switch (peek) { /* Global tokens
												  in state = ATTR */
			case 0x00: /* SWITCH_PAGE */
				*codepage_attr = tvb_get_guint8 (tvb, off+1);
				proto_tree_add_text (tree, tvb, off, 2,
						"      |  Attr | A -->%3d "
						"| SWITCH_PAGE (Attr code page)    |",
						*codepage_attr);
				off += 2;
				break;
			case 0x01: /* END */
				/* BEWARE
				 *   The Attribute END token means either ">" or "/>"
				 *   and as a consequence both must be treated separately.
				 *   This is done in the TAG state parser.
				 */
				off++;
				DebugLog(("ATTR: level = %u, Return: len = %u\n",
							level, off - offset));
				return (off - offset);
			case 0x02: /* ENTITY */
				ent = tvb_get_guintvar (tvb, off+1, &len);
				proto_tree_add_text (tree, tvb, off, 1+len,
						"  %3d |  Attr | A %3d    "
						"| ENTITY                          "
						"|     %s'&#%u;'",
						level, *codepage_attr, Indent (level), ent);
				off += 1+len;
				break;
			case 0x03: /* STR_I */
				len = tvb_strsize (tvb, off+1);
				proto_tree_add_text (tree, tvb, off, 1+len,
						"  %3d |  Attr | A %3d    "
						"| STR_I (Inline string)           "
						"|     %s\'%s\'",
						level, *codepage_attr, Indent (level),
						tvb_format_text (tvb, off+1, len-1));
				off += 1+len;
				break;
			case 0x04: /* LITERAL */
				index = tvb_get_guintvar (tvb, off+1, &len);
				str_len = tvb_strsize (tvb, str_tbl+index);
				proto_tree_add_text (tree, tvb, off, 1+len,
						"  %3d |  Attr | A %3d    "
						"| LITERAL (Literal Attribute)     "
						"|   %s<%s />",
						level, *codepage_attr, Indent (level),
						tvb_format_text (tvb, str_tbl+index, str_len-1));
				off += 1+len;
				break;
			case 0x40: /* EXT_I_0 */
			case 0x41: /* EXT_I_1 */
			case 0x42: /* EXT_I_2 */
				/* Extension tokens */
				len = tvb_strsize (tvb, off+1);
				proto_tree_add_text (tree, tvb, off, 1+len,
						"  %3d |  Attr | A %3d    "
						"| EXT_I_%1x    (Extension Token)    "
						"|     %s(Inline string extension: \'%s\')",
						level, *codepage_attr, peek & 0x0f, Indent (level),
						tvb_format_text (tvb, off+1, len-1));
				off += 1+len;
				break;
			/* 0x43 impossible in ATTR state */
			/* 0x44 impossible in ATTR state */
			case 0x80: /* EXT_T_0 */
			case 0x81: /* EXT_T_1 */
			case 0x82: /* EXT_T_2 */
				/* Extension tokens */
				index = tvb_get_guintvar (tvb, off+1, &len);
				str_len = tvb_strsize (tvb, str_tbl+index);
				proto_tree_add_text (tree, tvb, off, 1+len,
						"  %3d |  Attr | A %3d    "
						"| EXT_T_%1x    (Extension Token)    "
						"|     %s(Tableref string extension: \'%s\')",
						level, *codepage_attr, peek & 0x0f, Indent (level),
						tvb_format_text (tvb, str_tbl+index, str_len-1));
				off += 1+len;
				break;
			case 0x83: /* STR_T */
				index = tvb_get_guintvar (tvb, off+1, &len);
				str_len = tvb_strsize (tvb, str_tbl+index);
				proto_tree_add_text (tree, tvb, off, 1+len,
						"  %3d |  Attr | A %3d    "
						"| STR_T (Tableref string)         "
						"|     %s\'%s\'",
						level, *codepage_attr, Indent (level),
						tvb_format_text (tvb, str_tbl+index, str_len-1));
				off += 1+len;
				break;
			/* 0x84 impossible in ATTR state */
			case 0xC0: /* EXT_0 */
			case 0xC1: /* EXT_1 */
			case 0xC2: /* EXT_2 */
				/* Extension tokens */
				proto_tree_add_text (tree, tvb, off, 1,
						"  %3d |  Attr | A %3d    "
						"| EXT_%1x      (Extension Token)    "
						"|     %s(Single-byte extension)",
						level, *codepage_attr, peek & 0x0f, Indent (level));
				off++;
				break;
			case 0xC3: /* OPAQUE - WBXML 1.1 and newer */
				if (tvb_get_guint8 (tvb, 0)) { /* WBXML 1.x (x > 0) */
					index = tvb_get_guintvar (tvb, off+1, &len);
					proto_tree_add_text (tree, tvb, off, 1 + len + index,
							"  %3d |  Attr | A %3d    "
							"| OPAQUE (Opaque data)            "
							"|       %s(%d bytes of opaque data)",
							level, *codepage_attr, Indent (level), index);
					off += 1+len+index;
				} else { /* WBXML 1.0 - RESERVED_2 token (invalid) */
					proto_tree_add_text (tree, tvb, off, 1,
							"  %3d |  Attr | A %3d    "
							"| RESERVED_2     (Invalid Token!) "
							"| WBXML 1.0 parsing stops here.",
							level, *codepage_attr);
					/* Stop processing as it is impossible to parse now */
					off = tvb_len;
					DebugLog(("ATTR: level = %u, Return: len = %u\n",
								level, off - offset));
					return (off - offset);
				}
				break;
			/* 0xC4 impossible in ATTR state */
			default:
				proto_tree_add_text (tree, tvb, off, 1,
						"  %3d |  Attr | A %3d    "
						"| %-10s     (Invalid Token!) "
						"| WBXML parsing stops here.",
						level, *codepage_attr,
						match_strval (peek, vals_wbxml1x_global_tokens));
				/* Move to end of buffer */
				off = tvb_len;
				break;
		} else { /* Known atribute token */
			if (peek & 0x80) { /* attrValue */
				proto_tree_add_text (tree, tvb, off, 1,
						"  %3d |  Attr | A %3d    "
						"|   Known attrValue 0x%02X          "
						"|       %sattrValue_0x%02X",
						level, *codepage_attr, peek & 0x7f, Indent (level),
						peek);
				off++;
			} else { /* attrStart */
				proto_tree_add_text (tree, tvb, off, 1,
						"  %3d |  Attr | A %3d    "
						"|   Known attrStart 0x%02X          "
						"|   %sattrStart_0x%02X",
						level, *codepage_attr, peek & 0x7f, Indent (level),
						peek);
				off++;
			}
		}
	} /* End WHILE */
	DebugLog(("ATTR: level = %u, Return: len = %u (end of function body)\n",
				level, off - offset));
	return (off - offset);
}


/****************** Register the protocol with Ethereal ******************/


/* This format is required because a script is used to build the C function
 * that calls the protocol registration. */

void
proto_register_wbxml(void)
{ /* Setup list of header fields. See Section 1.6.1 for details. */
	static hf_register_info hf[] = {
		{ &hf_wbxml_version,
			{ "Version",
			  "wbxml.version",
			  FT_UINT8, BASE_HEX,
			  VALS ( vals_wbxml_versions ), 0x00,
			  "WBXML Version", HFILL }
		},
		{ &hf_wbxml_public_id_known,
			{ "Public Identifier (known)",
			  "wbxml.public_id.known",
			  FT_UINT32, BASE_HEX,
			  VALS ( vals_wbxml_public_ids ), 0x00,
			  "WBXML Known Public Identifier (integer)", HFILL }
		},
		{ &hf_wbxml_public_id_literal,
			{ "Public Identifier (literal)",
			  "wbxml.public_id.literal",
			  FT_STRING, BASE_NONE,
			  NULL, 0x00,
			  "WBXML Literal Public Identifier (text string)", HFILL }
		},
		{ &hf_wbxml_charset,
			{ "Character Set",
			  "wbxml.charset",
			  FT_UINT32, BASE_HEX,
			  VALS ( vals_character_sets ), 0x00,
			  "WBXML Character Set", HFILL }
		},
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_wbxml,
		&ett_wbxml_str_tbl,
		&ett_wbxml_content,
	};

	/* Register the protocol name and description */
	proto_wbxml = proto_register_protocol(
			"WAP Binary XML",
			"WBXML",
			"wbxml"
	);

	/* Required function calls to register the header fields
	 * and subtrees used */
	proto_register_field_array(proto_wbxml, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	register_dissector("wbxml", dissect_wbxml, proto_wbxml);
}


void
proto_reg_handoff_wbxml(void)
{
	dissector_handle_t wbxml_handle;

	/* Heuristic dissectors would be declared by means of:
	 * heur_dissector_add("wsp", dissect_wbxml_heur, proto_wbxml);
	 */

	wbxml_handle = create_dissector_handle(dissect_wbxml, proto_wbxml);

	/* Register the WSP content types (defined as protocol port)
	 * for WBXML dissection.
	 * 
	 * See http://www.wapforum.org/wina/wsp-content-type.htm
	 * 
	 * As the media types for WSP and HTTP are the same, the WSP dissector
	 * uses the same string dissector table as the HTTP protocol.
	 */

	/**** Well-known WBXML WSP Content-Type values ****/
	
	dissector_add_string("media_type",
			"application/vnd.wap.wmlc", wbxml_handle);
	dissector_add_string("media_type",
			"application/vnd.wap.wta-eventc", wbxml_handle);
	dissector_add_string("media_type",
			"application/vnd.wap.wbxml", wbxml_handle);
	dissector_add_string("media_type",
			"application/vnd.wap.sic", wbxml_handle);
	dissector_add_string("media_type",
			"application/vnd.wap.slc", wbxml_handle);
	dissector_add_string("media_type",
			"application/vnd.wap.coc", wbxml_handle);
	dissector_add_string("media_type",
			"application/vnd.wap.connectivity-wbxml", wbxml_handle);
	dissector_add_string("media_type",
			"application/vnd.wap.locc+wbxml", wbxml_handle);
	dissector_add_string("media_type",
			"application/vnd.syncml+wbxml", wbxml_handle);
	dissector_add_string("media_type",
			"application/vnd.syncml.dm+wbxml", wbxml_handle);
	dissector_add_string("media_type",
			"application/vnd.oma.drm.rights+wbxml", wbxml_handle);

	/**** Registered WBXML WSP Content-Type values ****/

	dissector_add_string("media_type",
			"application/vnd.uplanet.cacheop-wbxml", wbxml_handle);
	dissector_add_string("media_type",
			"application/vnd.uplanet.alert-wbxml", wbxml_handle);
	dissector_add_string("media_type",
			"application/vnd.uplanet.list-wbxml", wbxml_handle);
	dissector_add_string("media_type",
			"application/vnd.uplanet.listcmd-wbxml", wbxml_handle);
	dissector_add_string("media_type",
			"application/vnd.uplanet.channel-wbxml", wbxml_handle);
	dissector_add_string("media_type",
			"application/vnd.uplanet.bearer-choice-wbxml", wbxml_handle);
	dissector_add_string("media_type",
			"application/vnd.phonecom.mmc-wbxml", wbxml_handle);
	dissector_add_string("media_type",
			"application/vnd.nokia.syncset+wbxml", wbxml_handle);

	/***** Content types that only have a textual representation *****/
	dissector_add_string("media_type",
			"application/x-wap-prov.browser-bookmarks", wbxml_handle);
	dissector_add_string("media_type",
			"application/x-wap-prov.browser-settings", wbxml_handle);
	/* Same as application/vnd.nokia.syncset+wbxml */
	dissector_add_string("media_type",
			"application/x-prov.syncset+wbxml", wbxml_handle);
	
}
