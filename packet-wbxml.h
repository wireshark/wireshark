/* packet-wbxml.h
 * Routines for wbxml dissection
 * Copyright 2003, Olivier Biot <olivier.biot (ad) siemens.com>
 *
 * $Id: packet-wbxml.h,v 1.2 2003/02/12 01:17:02 guy Exp $
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
 *      WML 1.1 - Global tokens (EXT)      *
 *******************************************/
static const value_string vals_wmlc11_global[] = {
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
 *              WML 1.1 - Tags             *
 *******************************************/
static const value_string vals_wmlc11_tags[] = {
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
	{ 0x05, "sl" },

	{ 0x00, NULL }
};

/*******************************************
 *        SL 1.0 - Attribute Start         *
 *******************************************/
static const value_string vals_slc10_attrStart[] = {
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
	{ 0x05, "co" },
	{ 0x06, "invalidate-object" },
	{ 0x07, "invalidate-service" },

	{ 0x00, NULL }
};

/*******************************************
 *        CO 1.0 - Attribute Start         *
 *******************************************/
static const value_string vals_coc10_attrStart[] = {
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
	{ 0x85, "'.com/'" },
	{ 0x86, "'.edu/'" },
	{ 0x87, "'.net/'" },
	{ 0x88, "'.org/'" },

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
		FALSE, NULL, NULL, NULL, NULL
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
		FALSE, NULL, NULL, NULL, NULL
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
