/* packet-wbxml.h
 * Routines for wbxml dissection
 * Copyright 2003, Olivier Biot <olivier.biot (ad) siemens.com>
 *
 * $Id: packet-wbxml.h,v 1.3 2003/02/13 22:16:16 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 *
 * Wap Binary XML decoding functionality provided by Olivier Biot.
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

#ifndef PACKET_WBXML_H
#define PACKET_WBXML_H


/* See http://www.wapforum.org/wina/ for an up-to-date list. */
#define WBXML_WML_10		0x02
#define WBXML_WTA_10		0x03
#define WBXML_WML_11		0x04
#define WBXML_SI_10			0x05
#define WBXML_SL_10			0x06
#define WBXML_CO_10			0x07
#define WBXML_CHANNEL_10	0x08
#define WBXML_WML_12		0x09
#define WBXML_WML_13		0x0a
#define WBXML_PROV_10		0x0b
#define WBXML_WTAWML_12		0x0c
#define WBXML_EMN_10		0x0d
#define WBXML_DRMREL_10		0x0e

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
	
	{ 0x00, NULL }
};



static const value_string vals_wbxml_versions[] = {
	{ 0x00, "1.0" },
	{ 0x01, "1.1" },
	{ 0x02, "1.2" },
	{ 0x03, "1.3" },
	
	{ 0x00, NULL }
};

/* See WAP-104-WBXML */
static const value_string vals_wbxml10_global_tokens[] = {
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
	{ 0xC3, "RESERVED_2" },
	{ 0xC4, "LITERAL_AC" },

	{ 0x00, NULL }
};

/* See WAP-135-WBXML, WAP-154-WBXML, WAP-192-WBXML */
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


/****************************************************************************/

/*******************************************
 *      WML 1.0 - Global tokens (EXT)      *
 *******************************************/
static const value_string vals_wmlc10_global[] = {
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

/*******************************************
 *              WML 1.0 - Tags             *
 *******************************************/
static const value_string vals_wmlc10_tags[] = {
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

/*******************************************
 *       WML 1.0 - Attribute Start         *
 *******************************************/
static const value_string vals_wmlc10_attrStart[] = {
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

/*******************************************
 *       WML 1.0 - Attribute Value         *
 *******************************************/
static const value_string vals_wmlc10_attrValue[] = {
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

/****************************************************************************/

/*******************************************
 *      WML 1.1 - Global tokens (EXT)      *
 *******************************************/
#define vals_wmlc11_global  vals_wmlc10_global

/*******************************************
 *              WML 1.1 - Tags             *
 *******************************************/
static const value_string vals_wmlc11_tags[] = {
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

/*******************************************
 *       WML 1.1 - Attribute Start         *
 *******************************************/
static const value_string vals_wmlc11_attrStart[] = {
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

/*******************************************
 *       WML 1.1 - Attribute Value         *
 *******************************************/
static const value_string vals_wmlc11_attrValue[] = {
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

/****************************************************************************/

/*******************************************
 *      WML 1.2 - Global tokens (EXT)      *
 *******************************************/
#define vals_wmlc12_global vals_wmlc11_global
	
/*******************************************
 *              WML 1.2 - Tags             *
 *******************************************/
static const value_string vals_wmlc12_tags[] = {
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

/*******************************************
 *       WML 1.2 - Attribute Start         *
 *******************************************/
static const value_string vals_wmlc12_attrStart[] = {
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

/*******************************************
 *       WML 1.2 - Attribute Value         *
 *******************************************/
#define vals_wmlc12_attrValue vals_wmlc11_attrValue
/* Same as WML 1.1 */


/****************************************************************************/

/*******************************************
 *      WML 1.3 - Global tokens (EXT)      *
 *******************************************/
#define vals_wmlc13_global vals_wmlc11_global

/*******************************************
 *              WML 1.3 - Tags             *
 *******************************************/
#define vals_wmlc13_tags vals_wmlc12_tags
/* Same as WML 1.1 */

/*******************************************
 *       WML 1.3 - Attribute Start         *
 *******************************************/
static const value_string vals_wmlc13_attrStart[] = {
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

/*******************************************
 *       WML 1.3 - Attribute Value         *
 *******************************************/
#define vals_wmlc13_attrValue vals_wmlc11_attrValue
/* Same as WML 1.1 */


/****************************************************************************/

/*******************************************
 *      SI 1.0 - Global tokens (EXT)       *
 *******************************************/
static const value_string vals_sic10_global[] = {
	{ 0x00, NULL }
};


/*******************************************
 *           SI 1.0 - Tags                 *
 *******************************************/
static const value_string vals_sic10_tags[] = {
	/* 0x00 -- 0x04 GLOBAL */
	{ 0x05, "si" },
	{ 0x06, "indication" },
	{ 0x07, "info" },
	{ 0x08, "item" },

	{ 0x00, NULL }
};

/*******************************************
 *        SI 1.0 - Attribute Start         *
 *******************************************/
static const value_string vals_sic10_attrStart[] = {
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

/*******************************************
 *        SI 1.0 - Attribute Value         *
 *******************************************/
static const value_string vals_sic10_attrValue[] = {
	/* 0x80 -- 0x84 GLOBAL */
	{ 0x85, "'.com/'" },
	{ 0x86, "'.edu/'" },
	{ 0x87, "'.net/'" },
	{ 0x88, "'.org/'" },

	{ 0x00, NULL }
};

/****************************************************************************/


/*******************************************
 *      SL 1.0 - Global tokens (EXT)       *
 *******************************************/
static const value_string vals_slc10_global[] = {
	{ 0x00, NULL }
};


/*******************************************
 *           SL 1.0 - Tags                 *
 *******************************************/
static const value_string vals_slc10_tags[] = {
	/* 0x00 -- 0x04 GLOBAL */
	{ 0x05, "sl" },

	{ 0x00, NULL }
};

/*******************************************
 *        SL 1.0 - Attribute Start         *
 *******************************************/
static const value_string vals_slc10_attrStart[] = {
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

/*******************************************
 *        SL 1.0 - Attribute Value         *
 *******************************************/
static const value_string vals_slc10_attrValue[] = {
	/* 0x80 -- 0x84 GLOBAL */
	{ 0x85, "'.com/'" },
	{ 0x86, "'.edu/'" },
	{ 0x87, "'.net/'" },
	{ 0x88, "'.org/'" },

	{ 0x00, NULL }
};

/****************************************************************************/


/*******************************************
 *      CO 1.0 - Global tokens (EXT)       *
 *******************************************/
static const value_string vals_coc10_global[] = {
	{ 0x00, NULL }
};


/*******************************************
 *           CO 1.0 - Tags                 *
 *******************************************/
static const value_string vals_coc10_tags[] = {
	/* 0x00 -- 0x04 GLOBAL */
	{ 0x05, "co" },
	{ 0x06, "invalidate-object" },
	{ 0x07, "invalidate-service" },

	{ 0x00, NULL }
};

/*******************************************
 *        CO 1.0 - Attribute Start         *
 *******************************************/
static const value_string vals_coc10_attrStart[] = {
	/* 0x00 -- 0x04 GLOBAL */
	{ 0x05, "uri=" },
	{ 0x06, "uri='http://'" },
	{ 0x07, "uri='http://www.'" },
	{ 0x08, "uri='https://'" },
	{ 0x09, "uri='https://www.'" },

	{ 0x00, NULL }
};

/*******************************************
 *        CO 1.0 - Attribute Value         *
 *******************************************/
static const value_string vals_coc10_attrValue[] = {
	/* 0x80 -- 0x84 GLOBAL */
	{ 0x85, "'.com/'" },
	{ 0x86, "'.edu/'" },
	{ 0x87, "'.net/'" },
	{ 0x88, "'.org/'" },

	{ 0x00, NULL }
};


/****************************************************************************/


/*******************************************
 *      PROV 1.0 - Global tokens (EXT)       *
 *******************************************/
static const value_string vals_provc10_global[] = {
	{ 0x00, NULL }
};


/*******************************************
 *           PROV 1.0 - Tags                 *
 *******************************************/
static const value_string vals_provc10_tags[] = {
	/* 0x00 -- 0x04 GLOBAL */
	{ 0x05, "wap-provisioningdoc" },
	{ 0x06, "characteristic" },
	{ 0x07, "parm" },

	{ 0x00, NULL }
};

/*******************************************
 *        PROV 1.0 - Attribute Start         *
 *******************************************/
static const value_string vals_provc10_attrStart[] = {
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
	/* 0x3D -- 0x3F */
	/* 0x40 -- 0x44 GLOBAL */
	{ 0x45, "version=" },
	{ 0x46, "version='1.0'" },
	/* 0x47 -- 0x4F */
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

	{ 0x00, NULL }
};

/*******************************************
 *        PROV 1.0 - Attribute Value         *
 *******************************************/
static const value_string vals_provc10_attrValue[] = {
	/* 0x80 -- 0x84 GLOBAL */
	{ 0x85, "IPV4" },
	{ 0x86, "IPV6" },
	{ 0x87, "E164" },
	{ 0x88, "ALPHA" },
	{ 0x89, "APN" },
	{ 0x8A, "SCODE" },
	{ 0x8B, "TETRA-ITSI" },
	{ 0x8C, "MAN" },
	/* 0x8D -- 0x8F */
	{ 0x90, "ANALOG-MODEM" },
	{ 0x91, "V.120" },
	{ 0x92, "V.110" },
	{ 0x93, "X.31" },
	{ 0x94, "BIT-TRANSPARENT" },
	{ 0x95, "DIRECT-ASYNCHRONOUS-DATA-SERVICE" },
	/* 0x96 -- 0x99 */
	{ 0x9A, "PAP" },
	{ 0x9B, "CHAP" },
	{ 0x9C, "HTTP-BASIC" },
	{ 0x9D, "HTTP-DIGEST" },
	{ 0x9E, "WTLS-SS" },
	/* 0x9F -- 0xA1 */
	{ 0xA2, "GSM-USSD" },
	{ 0xA3, "GSM-SMS" },
	{ 0xA4, "ANSI-136-GUTS" },
	{ 0xA5, "IS-95-CDMA-SMS" },
	{ 0xA6, "IS-95-CDMA-CSD" },
	{ 0xA7, "IS-95-CDMA-PACKET" },
	{ 0xA8, "ANSI-136-CSD" },
	{ 0xA9, "ANSI-136-GPRS" },
	{ 0xAA, "GSM-CSD" },
	{ 0xAB, "GSM-GPRS" },
	{ 0xAC, "AMPS-CDPD" },
	{ 0xAD, "PDC-CSD" },
	{ 0xAE, "PDC-PACKET" },
	{ 0xAF, "IDEN-SMS" },
	{ 0xB0, "IDEN-CSD" },
	{ 0xB1, "IDEN-PACKET" },
	{ 0xB2, "FLEX/REFLEX" },
	{ 0xB3, "PHS-SMS" },
	{ 0xB4, "PHS-CSD" },
	{ 0xB5, "TETRA-SDS" },
	{ 0xB6, "TETRA-PACKET" },
	{ 0xB7, "ANSI-136-GHOST" },
	{ 0xB8, "MOBITEX-MPAK" },
	/* 0xB9 -- 0xBF */
	/* 0xC0 -- 0xC4 GLOBAL */
	{ 0xC5, "AUTOBAUDING" },
	/* 0xC6 -- 0xC9 */
	{ 0xCA, "CL-WSP" },
	{ 0xCB, "CO-WSP" },
	{ 0xCC, "CL-SEC-WSP" },
	{ 0xCD, "CO-SEC-WSP" },
	{ 0xCE, "CL-SEC-WTA" },
	{ 0xCF, "CO-SEC-WTA" },

	{ 0x00, NULL }
};


/****************************************************************************/





/* The following definitions must be put at the very end of this header file,
 * as the struct object contains references to objects defined above!
 */

typedef struct {
	const guint8 defined;
	const value_string *global;
	const value_string *tags;
	const value_string *attrStart;
	const value_string *attrValue;
} wbxml_mapping_table;

/* BEWARE: values 0 and 1 are not defined, so we start from 2
 */
static const wbxml_mapping_table wbxml_map[] = {
	{ /* 0x00 = literal public identifier */
		FALSE, NULL, NULL, NULL, NULL
	},
	{ /* 0x01 = Unknown or missing public identifier */
		FALSE, NULL, NULL, NULL, NULL
	},
	{ /* 0x02 = WML 1.0 */
		TRUE, vals_wmlc10_global, vals_wmlc10_tags,
		vals_wmlc10_attrStart, vals_wmlc10_attrValue
	},
	{ /* 0x03 = WTA 1.0 - Deprecated */
		FALSE, NULL, NULL, NULL, NULL
	},
	{ /* 0x04 = WML 1.1 */
		TRUE, vals_wmlc11_global, vals_wmlc11_tags,
		vals_wmlc11_attrStart, vals_wmlc11_attrValue
	},
	{ /* 0x05 = SI 1.0 */
		TRUE, vals_sic10_global, vals_sic10_tags,
		vals_sic10_attrStart, vals_sic10_attrValue
	},
	{ /* 0x06 = SL 1.0 */
		TRUE, vals_slc10_global, vals_slc10_tags,
		vals_slc10_attrStart, vals_slc10_attrValue
	},
	{ /* 0x07 = CO 1.0 */
		TRUE, vals_coc10_global, vals_coc10_tags,
		vals_coc10_attrStart, vals_coc10_attrValue
	},
	{ /* 0x08 = CHANNEL 1.0 */
		FALSE, NULL, NULL, NULL, NULL
	},
	{ /* 0x09 = WML 1.2 */
		TRUE, vals_wmlc12_global, vals_wmlc12_tags,
		vals_wmlc12_attrStart, vals_wmlc12_attrValue
	},
	{ /* 0x0A = WML 1.3 */
		TRUE, vals_wmlc13_global, vals_wmlc13_tags,
		vals_wmlc13_attrStart, vals_wmlc13_attrValue
	},
	{ /* 0x0B = PROV 1.0 */
		TRUE, vals_provc10_global, vals_provc10_tags,
		vals_provc10_attrStart, vals_provc10_attrValue
	},
	{ /* 0x0C = WTA-WML 1.2 */
		FALSE, NULL, NULL, NULL, NULL
	},
	{ /* 0x0D = EMN 1.0 */
		FALSE, NULL, NULL, NULL, NULL
	},
	{ /* 0x0E = DRMREL 1.0 */
		FALSE, NULL, NULL, NULL, NULL
	},
};
/* Update the entry below when the table above is appended */
#define WBXML_MAP_MAX_ID 0x0E

#endif
