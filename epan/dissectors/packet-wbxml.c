/* packet-wbxml.c
 *
 * Routines for WAP Binary XML dissection
 * Copyright 2003, 2004, Olivier Biot.
 *
 * $Id$
 *
 * Refer to the AUTHORS file or the AUTHORS section in the man page
 * for contacting the author(s) of this file.
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 *
 * WAP Binary XML decoding functionality provided by Olivier Biot.
 * 
 * The WAP specifications used to be found at the WAP Forum:
 *	<http://www.wapforum.org/what/Technical.htm>
 * But now the correct link is at the Open Mobile Alliance:
 *	<http://www.openmobilealliance.org/tech/affiliates/wap/wapindex.html>
 * Media types defined by OMA affiliates will have their standards at:
 *	<http://www.openmobilealliance.org/tech/affiliates/index.html>
 *	<http://www.openmobilealliance.org/release_program/index.html>
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

#include <epan/packet.h>

#include <epan/prefs.h>
#include <epan/emem.h>

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
 * "wbxml_decoding" structure.
 *
 * NOTES:
 *
 *  - Some WBXML content is *not* backwards compatible across minor versions.
 *    This painful remark is true for:
 *      o  WMLC 1.0 with respect to later WMLC 1.x
 *      o  All WV-CSP versions (never backwards compatible)
 *    The only way of correctly rendering the WBXML is to let the end-user
 *    choose from the possible renderings. This only applies to the case when
 *    the WBXML DocType is not included in the WBXML header (unknown/missing).
 *
 *  - Some WBXML content uses EXT_T_* in a non-tableref manner. This is the
 *    case with WV-CSP 1.1 and up, where the index points to a value_string
 *    containing WV-CSP specific token values. This is allowed as it is not
 *    explicitly forbidden in the WBXML specifications. Hence the global token
 *    map for content must also contain a function pointer if no tableref
 *    string is used.
 *
 *  - Code page switches apply until a new code page switch. In the WBXML/1.x
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
 *    identifier specified in the WBXML header. This has to do with the
 *    decoding of terminated text strings in the different character codings.
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

/* Note on Token mapping
 * ---------------------
 *
 * The WBXML dissector will try mapping the token decoding to their textual
 * representation if the media type has a defined token representation. The
 * following logic applies:
 *
 * a. Inspect the WBXML PublicID
 *	This means that I need a list { PublicID, decoding }
 *
 * b. Inspect the literal media type
 *	This requires a list { "media/type", discriminator, { decodings } }
 *
 *   b.1. Use a discriminator to choose an appropriate token mapping;
 *	The disciminator needs a small number of bytes from the data tvbuff_t.
 *
 * else
 *   b.2. Provide a list to the end-user with all possible token mappings.
 *
 * c. If none match then only show the tokens without mapping.
 *
 */

/* ext_t_func_ptr is a pointer to a function handling the EXT_T_i tokens:
 *
 * char * ext_t_function(tvbuff_t *tvb, guint32 value, guint32 strtbl);
 */
typedef char * (* ext_t_func_ptr)(tvbuff_t *, guint32, guint32);

/* Note on parsing of OPAQUE data
 * ------------------------------
 *
 * The WBXML encapsulation allows the insertion of opaque binary data in the
 * WBXML body. Although this opaque data has no meaning in WBXML, the media
 * type itself may define compact encoding of given input by encoding it in
 * such a OPAQUE blob of bytes.
 *
 * The WBXML dissector now supports dissection of OPAQUE data by means of a
 * mapping function that will operate based on the token (well-known or literal)
 * and the active code page.
 *
 * For well-known tokens the simplest approach is to use a switch for the code
 * pages and another switch for the relevant tokens within a code page.
 *
 * For literal tokens (tags and attribute names), the only approach is a string
 * comparison with the literal representation of the given tag or attribute
 * name.
 *
 * opaque_token_func_ptr is a pointer to a function handling OPAQUE values
 * for binary tokens representing tags or attribute starts.
 * opaque_literal_func_ptr is a pointer to a function handling OPAQUE values
 * for literal tokens representing tags or attribute starts.
 * 
 * The length field of the OPAQUE entry starts at offset (not offset + 1).
 * 
 * The length of the processed OPAQUE value is returned by reference.
 *
 * char * opaque_token_function(tvbuff_t *tvb, guint32 offset,
 * 		guint8 token, guint8 codepage, guint32 *length);
 * char * opaque_literal_function(tvbuff_t *tvb, guint32 offset,
 * 		const char *token, guint8 codepage, guint32 *length);
 */
typedef char * (* opaque_token_func_ptr)(tvbuff_t *, guint32, guint8, guint8, guint32 *);
typedef char * (* opaque_literal_func_ptr)(tvbuff_t *, guint32, const char *, guint8, guint32 *);

static char *
default_opaque_binary_tag(tvbuff_t *tvb, guint32 offset,
		guint8 token _U_, guint8 codepage _U_, guint32 *length)
{
	guint32 data_len = tvb_get_guintvar(tvb, offset, length);
	char *str = g_strdup_printf("(%d bytes of opaque data)", data_len);
	*length += data_len;
	return str;
}

static char *
default_opaque_literal_tag(tvbuff_t *tvb, guint32 offset,
		const char *token _U_, guint8 codepage _U_, guint32 *length)
{
	guint32 data_len = tvb_get_guintvar(tvb, offset, length);
	char *str = g_strdup_printf("(%d bytes of opaque data)", data_len);
	*length += data_len;
	return str;
}

static char *
default_opaque_binary_attr(tvbuff_t *tvb, guint32 offset,
		guint8 token _U_, guint8 codepage _U_, guint32 *length)
{
	guint32 data_len = tvb_get_guintvar(tvb, offset, length);
	char *str = g_strdup_printf("(%d bytes of opaque data)", data_len);
	*length += data_len;
	return str;
}

static char *
default_opaque_literal_attr(tvbuff_t *tvb, guint32 offset,
		const char *token _U_, guint8 codepage _U_, guint32 *length)
{
	guint32 data_len = tvb_get_guintvar(tvb, offset, length);
	char *str = g_strdup_printf("(%d bytes of opaque data)", data_len);
	*length += data_len;
	return str;
}

/* Render a hex %dateTime encoded timestamp as a string.
 * 0x20011231123456 becomes "2001-12-31T12:34:56Z" */
static char *
date_time_from_opaque(tvbuff_t *tvb, guint32 offset, guint32 data_len)
{
	char *str;

	switch (data_len) {
		case 4: /* YYYY-MM-DD[T00:00:00Z] */
			str = g_strdup_printf("%%DateTime: "
					"%02x%02x-%02x-%02xT00:00:00Z",
					tvb_get_guint8(tvb, offset),
					tvb_get_guint8(tvb, offset + 1),
					tvb_get_guint8(tvb, offset + 2),
					tvb_get_guint8(tvb, offset + 3));
			break;
		case 5: /* YYYY-MM-DDThh[:00:00Z] */
			str = g_strdup_printf("%%DateTime: "
					"%02x%02x-%02x-%02xT%02x:00:00Z",
					tvb_get_guint8(tvb, offset),
					tvb_get_guint8(tvb, offset + 1),
					tvb_get_guint8(tvb, offset + 2),
					tvb_get_guint8(tvb, offset + 3),
					tvb_get_guint8(tvb, offset + 4));
			break;
		case 6: /* YYYY-MM-DDThh:mm[:00Z] */
			str = g_strdup_printf("%%DateTime: "
					"%02x%02x-%02x-%02xT%02x:%02x:00Z",
					tvb_get_guint8(tvb, offset),
					tvb_get_guint8(tvb, offset + 1),
					tvb_get_guint8(tvb, offset + 2),
					tvb_get_guint8(tvb, offset + 3),
					tvb_get_guint8(tvb, offset + 4),
					tvb_get_guint8(tvb, offset + 5));
			break;
		case 7: /* YYYY-MM-DDThh:mm[:00Z] */
			str = g_strdup_printf("%%DateTime: "
					"%02x%02x-%02x-%02xT%02x:%02x:%02xZ",
					tvb_get_guint8(tvb, offset),
					tvb_get_guint8(tvb, offset + 1),
					tvb_get_guint8(tvb, offset + 2),
					tvb_get_guint8(tvb, offset + 3),
					tvb_get_guint8(tvb, offset + 4),
					tvb_get_guint8(tvb, offset + 5),
					tvb_get_guint8(tvb, offset + 6));
			break;
		default:
			str = g_strdup_printf("<Error: invalid binary %%DateTime "
					"(%d bytes of opaque data)>", data_len);
			break;
	}

	return str;
}

/* Is ALWAYS 6 bytes long:
 * 00YY YYYY  YYYY YYMM  MMDD DDDh  hhhh mmmm  mmss ssss  ZZZZ ZZZZ */
static char *
wv_datetime_from_opaque(tvbuff_t *tvb, guint32 offset, guint32 data_len)
{
	char *str;
	guint16 year;
	guint8 month, day, hour, minute, second, timezone;
	guint8 peek;

	if (data_len == 6) { /* Valid */

		/* Octet 1: 00YY YYYY */
		year = tvb_get_guint8(tvb, offset) & 0x3F; /* ..11 1111 */
		year <<=6;
		/* Octet 2: YYYY YYMM */
		peek = tvb_get_guint8(tvb, offset + 1);
		year += (peek >> 2); /* 1111 11.. */
		month = (peek & 0x03) << 2; /* .... ..11 */
		/* Octet 3: MMDD DDDh */
		peek = tvb_get_guint8(tvb, offset + 2);
		month += (peek >> 6); /* 11.. .... */
		day = (peek & 0x3E) >> 1; /* ..11 111. */
		hour = (peek & 0x01) << 4; /* .... ...1 */
		/* Octet 4: hhhh mmmm */
		peek = tvb_get_guint8(tvb, offset + 3);
		hour += (peek >> 4);
		minute = (peek & 0x0F) << 2; /* .... 1111 */
		/* Octet 5: mmss ssss */
		peek = tvb_get_guint8(tvb, offset + 4);
		minute += (peek >> 6); /* 11.. .... */
		second = peek & 0x3F; /* ..11 1111 */
		/* octet 6: ZZZZZZZZ */
		timezone = tvb_get_guint8(tvb, offset + 5);
		/* Now construct the string */
		str = g_strdup_printf("WV-CSP DateTime: "
				"%04d-%02d-%02dT%02d:%02d:%02d%c",
				year, month, day, hour, minute, second, timezone);
	} else { /* Invalid length for a WV-CSP DateTime tag value */
		str = g_strdup_printf("<Error: invalid binary WV-CSP DateTime value "
				"(%d bytes of opaque data)>", data_len);
	}
	return str;
}

/* WV-CSP integer values for tag content is encoded in a fashion similar
 * to a Long-Integer in WSP */
static char *
wv_integer_from_opaque(tvbuff_t *tvb, guint32 offset, guint32 data_len)
{
	char *str;

	switch (data_len) {
		case 1:
			str = g_strdup_printf("WV-CSP Integer: %d",
					tvb_get_guint8(tvb, offset));
			break;
		case 2:
			str = g_strdup_printf("WV-CSP Integer: %d",
					tvb_get_ntohs(tvb, offset));
			break;
		case 3:
			str = g_strdup_printf("WV-CSP Integer: %d",
					tvb_get_ntoh24(tvb, offset));
			break;
		case 4:
			str = g_strdup_printf("WV-CSP Integer: %d",
					tvb_get_ntohl(tvb, offset));
			break;
		default:
			str = g_strdup_printf("<Error: invalid binary WV-CSP Integer value "
					"(%d bytes of opaque data)>", data_len);
			break;
	}

	return str;
}

static char *
wv_csp10_opaque_literal_tag(tvbuff_t *tvb, guint32 offset,
		const char *token, guint8 codepage _U_, guint32 *length)
{
	guint32 data_len = tvb_get_guintvar(tvb, offset, length);
	char *str = NULL;

	if (   (strcmp(token, "Code") == 0)
		|| (strcmp(token, "ContentSize") == 0)
		|| (strcmp(token, "MessageCount") == 0)
		|| (strcmp(token, "Validity") == 0)
		|| (strcmp(token, "KeepAliveTime") == 0)
		|| (strcmp(token, "TimeToLive") == 0)
		|| (strcmp(token, "AcceptedContentLength") == 0)
		|| (strcmp(token, "MultiTrans") == 0)
		|| (strcmp(token, "ParserSize") == 0)
		|| (strcmp(token, "ServerPollMin") == 0)
		|| (strcmp(token, "TCPAddress") == 0)
		|| (strcmp(token, "TCPPort") == 0)
		|| (strcmp(token, "UDPPort") == 0) )
	{
		str = wv_integer_from_opaque(tvb, offset + *length, data_len);
	}
	else if (strcmp(token, "DateTime") == 0)
	{
		str = wv_datetime_from_opaque(tvb, offset + *length, data_len);
	}

	if (str == NULL) { /* Error, or not parsed */
		str = g_strdup_printf("(%d bytes of unparsed opaque data)", data_len);
	}
	*length += data_len;
	return str;
}

static char *
wv_csp10_opaque_binary_tag(tvbuff_t *tvb, guint32 offset,
		guint8 token, guint8 codepage, guint32 *length)
{
	guint32 data_len = tvb_get_guintvar(tvb, offset, length);
	char *str = NULL;

	switch (codepage) {
		case 0: /* Common code page */
			switch (token) {
				case 0x0B: /* <Code> */
				case 0x0F: /* <ContentSize> */
				case 0x1A: /* <MessageCount> */
				case 0x3C: /* <Validity> */
					str = wv_integer_from_opaque(tvb,
							offset + *length, data_len);
					break;
				case 0x11: /* <DateTime> */
					str = wv_datetime_from_opaque(tvb,
							offset + *length, data_len);
					break;
				default:
					break;
			}
			break;
		case 1: /* Access code page */
			switch (token) {
				case 0x1C: /* <KeepAliveTime> */
				case 0x32: /* <TimeToLive> */
					str = wv_integer_from_opaque(tvb,
							offset + *length, data_len);
					break;
				default:
					break;
			}
		case 3: /* Client capability code page */
			switch (token) {
				case 0x06: /* <AcceptedContentLength> */
				case 0x0C: /* <MultiTrans> */
				case 0x0D: /* <ParserSize> */
				case 0x0E: /* <ServerPollMin> */
				case 0x11: /* <TCPAddress> */
				case 0x12: /* <TCPPort> */
				case 0x13: /* <UDPPort> */
					str = wv_integer_from_opaque(tvb,
							offset + *length, data_len);
					break;
				default:
					break;
			}
			break;
		default:
			break;
	}
	if (str == NULL) { /* Error, or not parsed */
		str = g_strdup_printf("(%d bytes of unparsed opaque data)", data_len);
	}
	*length += data_len;

	return str;
}

static char *
wv_csp11_opaque_literal_tag(tvbuff_t *tvb, guint32 offset,
		const char *token, guint8 codepage _U_, guint32 *length)
{
	guint32 data_len = tvb_get_guintvar(tvb, offset, length);
	char *str = NULL;

	if (   (strcmp(token, "Code") == 0)
		|| (strcmp(token, "ContentSize") == 0)
		|| (strcmp(token, "MessageCount") == 0)
		|| (strcmp(token, "Validity") == 0)
		|| (strcmp(token, "KeepAliveTime") == 0)
		|| (strcmp(token, "TimeToLive") == 0)
		|| (strcmp(token, "AcceptedContentLength") == 0)
		|| (strcmp(token, "MultiTrans") == 0)
		|| (strcmp(token, "ParserSize") == 0)
		|| (strcmp(token, "ServerPollMin") == 0)
		|| (strcmp(token, "TCPPort") == 0)
		|| (strcmp(token, "UDPPort") == 0) )
	{
		str = wv_integer_from_opaque(tvb, offset + *length, data_len);
	}
	else
	if (   (strcmp(token, "DateTime") == 0)
		|| (strcmp(token, "DeliveryTime") == 0) )
	{
		str = wv_datetime_from_opaque(tvb, offset + *length, data_len);
	}

	if (str == NULL) { /* Error, or not parsed */
		str = g_strdup_printf("(%d bytes of unparsed opaque data)", data_len);
	}
	*length += data_len;
	return str;
}

static char *
wv_csp11_opaque_binary_tag(tvbuff_t *tvb, guint32 offset,
		guint8 token, guint8 codepage, guint32 *length)
{
	guint32 data_len = tvb_get_guintvar(tvb, offset, length);
	char *str = NULL;

	switch (codepage) {
		case 0: /* Common code page */
			switch (token) {
				case 0x0B: /* <Code> */
				case 0x0F: /* <ContentSize> */
				case 0x1A: /* <MessageCount> */
				case 0x3C: /* <Validity> */
					str = wv_integer_from_opaque(tvb,
							offset + *length, data_len);
					break;
				case 0x11: /* <DateTime> */
					str = wv_datetime_from_opaque(tvb,
							offset + *length, data_len);
					break;
				default:
					break;
			}
			break;
		case 1: /* Access code page */
			switch (token) {
				case 0x1C: /* <KeepAliveTime> */
				case 0x32: /* <TimeToLive> */
					str = wv_integer_from_opaque(tvb,
							offset + *length, data_len);
					break;
				default:
					break;
			}
		case 3: /* Client capability code page */
			switch (token) {
				case 0x06: /* <AcceptedContentLength> */
				case 0x0C: /* <MultiTrans> */
				case 0x0D: /* <ParserSize> */
				case 0x0E: /* <ServerPollMin> */
				case 0x12: /* <TCPPort> */
				case 0x13: /* <UDPPort> */
					str = wv_integer_from_opaque(tvb,
							offset + *length, data_len);
					break;
				default:
					break;
			}
			break;
		case 6: /* Messaging code page */
			switch (token) {
				case 0x1A: /* <DeliveryTime> - not in 1.0 */
					str = wv_datetime_from_opaque(tvb,
							offset + *length, data_len);
					break;
				default:
					break;
			}
			break;
		default:
			break;
	}
	if (str == NULL) { /* Error, or not parsed */
		str = g_strdup_printf("(%d bytes of unparsed opaque data)", data_len);
	}
	*length += data_len;

	return str;
}

static char *
wv_csp12_opaque_literal_tag(tvbuff_t *tvb, guint32 offset,
		const char *token, guint8 codepage _U_, guint32 *length)
{
	guint32 data_len = tvb_get_guintvar(tvb, offset, length);
	char *str = NULL;

	if (   (strcmp(token, "Code") == 0)
		|| (strcmp(token, "ContentSize") == 0)
		|| (strcmp(token, "MessageCount") == 0)
		|| (strcmp(token, "Validity") == 0)
		|| (strcmp(token, "KeepAliveTime") == 0)
		|| (strcmp(token, "TimeToLive") == 0)
		|| (strcmp(token, "AcceptedContentLength") == 0)
		|| (strcmp(token, "MultiTrans") == 0)
		|| (strcmp(token, "ParserSize") == 0)
		|| (strcmp(token, "ServerPollMin") == 0)
		|| (strcmp(token, "TCPPort") == 0)
		|| (strcmp(token, "UDPPort") == 0)
		|| (strcmp(token, "HistoryPeriod") == 0)
		|| (strcmp(token, "MaxWatcherList") == 0) )
	{
		str = wv_integer_from_opaque(tvb, offset + *length, data_len);
	}
	else
	if (   (strcmp(token, "DateTime") == 0)
		|| (strcmp(token, "DeliveryTime") == 0) )
	{
		str = wv_datetime_from_opaque(tvb, offset + *length, data_len);
	}

	if (str == NULL) { /* Error, or not parsed */
		str = g_strdup_printf("(%d bytes of unparsed opaque data)", data_len);
	}
	*length += data_len;
	return str;
}

static char *
wv_csp12_opaque_binary_tag(tvbuff_t *tvb, guint32 offset,
		guint8 token, guint8 codepage, guint32 *length)
{
	guint32 data_len = tvb_get_guintvar(tvb, offset, length);
	char *str = NULL;

	switch (codepage) {
		case 0: /* Common code page */
			switch (token) {
				case 0x0B: /* <Code> */
				case 0x0F: /* <ContentSize> */
				case 0x1A: /* <MessageCount> */
				case 0x3C: /* <Validity> */
					str = wv_integer_from_opaque(tvb,
							offset + *length, data_len);
					break;
				case 0x11: /* <DateTime> */
					str = wv_datetime_from_opaque(tvb,
							offset + *length, data_len);
					break;
				default:
					break;
			}
			break;
		case 1: /* Access code page */
			switch (token) {
				case 0x1C: /* <KeepAliveTime> */
				case 0x32: /* <TimeToLive> */
					str = wv_integer_from_opaque(tvb,
							offset + *length, data_len);
					break;
				default:
					break;
			}
		case 3: /* Client capability code page */
			switch (token) {
				case 0x06: /* <AcceptedContentLength> */
				case 0x0C: /* <MultiTrans> */
				case 0x0D: /* <ParserSize> */
				case 0x0E: /* <ServerPollMin> */
				case 0x12: /* <TCPPort> */
				case 0x13: /* <UDPPort> */
					str = wv_integer_from_opaque(tvb,
							offset + *length, data_len);
					break;
				default:
					break;
			}
			break;
		case 6: /* Messaging code page */
			switch (token) {
				case 0x1A: /* <DeliveryTime> - not in 1.0 */
					str = wv_datetime_from_opaque(tvb,
							offset + *length, data_len);
					break;
				default:
					break;
			}
			break;
		case 9: /* Common code page (continued) */
			switch (token) {
				case 0x08: /* <HistoryPeriod> - 1.2 only */
				case 0x0A: /* <MaxWatcherList> - 1.2 only */
					str = wv_integer_from_opaque(tvb,
							offset + *length, data_len);
					break;
				default:
					break;
			}
			break;
		default:
			break;
	}
	if (str == NULL) { /* Error, or not parsed */
		str = g_strdup_printf("(%d bytes of unparsed opaque data)", data_len);
	}
	*length += data_len;

	return str;
}

static char *
sic10_opaque_literal_attr(tvbuff_t *tvb, guint32 offset,
		const char *token, guint8 codepage _U_, guint32 *length)
{
	guint32 data_len = tvb_get_guintvar(tvb, offset, length);
	char *str = NULL;

	if (   (strcmp(token, "created") == 0)
		|| (strcmp(token, "si-expires") == 0) )
	{
		str = date_time_from_opaque(tvb, offset + *length, data_len);
	}
	if (str == NULL) { /* Error, or not parsed */
		str = g_strdup_printf("(%d bytes of unparsed opaque data)", data_len);
	}
	*length += data_len;

	return str;
}

static char *
sic10_opaque_binary_attr(tvbuff_t *tvb, guint32 offset,
		guint8 token, guint8 codepage, guint32 *length)
{
	guint32 data_len = tvb_get_guintvar(tvb, offset, length);
	char *str = NULL;

	switch (codepage) {
		case 0: /* Only valid codepage for SI */
			switch (token) {
				case 0x0A: /* created= */
				case 0x10: /* si-expires= */
					str = date_time_from_opaque(tvb,
							offset + *length, data_len);
					break;
				default:
					break;
			}
			break;
		default:
			break;
	}
	if (str == NULL) { /* Error, or not parsed */
		str = g_strdup_printf("(%d bytes of unparsed opaque data)", data_len);
	}
	*length += data_len;

	return str;
}

static char *
emnc10_opaque_literal_attr(tvbuff_t *tvb, guint32 offset,
		const char *token, guint8 codepage _U_, guint32 *length)
{
	guint32 data_len = tvb_get_guintvar(tvb, offset, length);
	char *str = NULL;

	if (   (strcmp(token, "timestamp") == 0) )
	{
		str = date_time_from_opaque(tvb, offset + *length, data_len);
	}
	if (str == NULL) { /* Error, or not parsed */
		str = g_strdup_printf("(%d bytes of unparsed opaque data)", data_len);
	}
	*length += data_len;

	return str;
}

static char *
emnc10_opaque_binary_attr(tvbuff_t *tvb, guint32 offset,
		guint8 token, guint8 codepage, guint32 *length)
{
	guint32 data_len = tvb_get_guintvar(tvb, offset, length);
	char *str = NULL;

	switch (codepage) {
		case 0: /* Only valid codepage for EMN */
			switch (token) {
				case 0x05: /* timestamp= */
					str = date_time_from_opaque(tvb,
							offset + *length, data_len);
					break;
				default:
					break;
			}
			break;
		default:
			break;
	}
	if (str == NULL) { /* Error, or not parsed */
		str = g_strdup_printf("(%d bytes of unparsed opaque data)", data_len);
	}
	*length += data_len;

	return str;
}

typedef struct _wbxml_decoding {
    const char *name;
    const char *abbrev;
    ext_t_func_ptr ext_t[3];
	opaque_token_func_ptr	opaque_binary_tag;
	opaque_literal_func_ptr	opaque_literal_tag;
	opaque_token_func_ptr	opaque_binary_attr;
	opaque_literal_func_ptr	opaque_literal_attr;
    const value_valuestring *global;
    const value_valuestring *tags;
    const value_valuestring *attrStart;
    const value_valuestring *attrValue;
} wbxml_decoding;

/* Define a pointer to a discriminator function taking a tvb and the start
 * offset of the WBXML tokens in the body as arguments.
 */
typedef const wbxml_decoding * (* discriminator_func_ptr)(tvbuff_t *, guint32);

/* For the decoding lists based on the known WBXML public ID */
typedef struct _wbxml_integer_list {
    guint32 public_id;
    const wbxml_decoding *map;
} wbxml_integer_list;

/* For the decoding lists on the literal content type */ 
typedef struct _wbxml_literal_list {
    const char *content_type;
    discriminator_func_ptr discriminator; /* TODO */
    const wbxml_decoding *map;
} wbxml_literal_list;

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

/* WBXML Preferences */
static gboolean skip_wbxml_token_mapping = FALSE;
static gboolean disable_wbxml_token_parsing = FALSE;


/**************** WBXML related declarations and definitions ****************/


/* WBXML public ID mappings. For an up-to-date list, see
 * http://www.openmobilealliance.org/tech/omna/ */
static const value_string vals_wbxml_public_ids[] = {
	/* 0x00 = literal public identifier */
	{ 0x01, "Unknown / missing Public Identifier" },
	{ 0x02, "-//WAPFORUM//DTD WML 1.0//EN (WML 1.0)" },
	{ 0x03, "-//WAPFORUM//DTD WTA 1.0//EN (WTA Event 1.0) - Deprecated" },
	{ 0x04, "-//WAPFORUM//DTD WML 1.1//EN (WML 1.1)" },
	{ 0x05, "-//WAPFORUM//DTD SI 1.0//EN (Service Indication 1.0)" },
	{ 0x06, "-//WAPFORUM//DTD SL 1.0//EN (Service Loading 1.0)" },
	{ 0x07, "-//WAPFORUM//DTD CO 1.0//EN (Cache Operation 1.0)" },
	{ 0x08, "-//WAPFORUM//DTD CHANNEL 1.1//EN (Channel 1.1)" },
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
static char *
ext_t_0_wml_10(tvbuff_t *tvb, guint32 value, guint32 str_tbl)
{
    gint str_len = tvb_strsize (tvb, str_tbl + value);
    char *str = g_strdup_printf("Variable substitution - escaped: '%s'",
	    tvb_get_ptr(tvb, str_tbl + value, str_len));
    return str;
}

static char *
ext_t_1_wml_10(tvbuff_t *tvb, guint32 value, guint32 str_tbl)
{
    gint str_len = tvb_strsize (tvb, str_tbl + value);
    char *str = g_strdup_printf("Variable substitution - unescaped: '%s'",
	    tvb_get_ptr(tvb, str_tbl + value, str_len));
    return str;
}

static char *
ext_t_2_wml_10(tvbuff_t *tvb, guint32 value, guint32 str_tbl)
{
    gint str_len = tvb_strsize (tvb, str_tbl + value);
    char *str = g_strdup_printf("Variable substitution - no transformation: '%s'",
	    tvb_get_ptr(tvb, str_tbl + value, str_len));
    return str;
}
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
	/* 0x05 -- 0x21 */
	{ 0x22, "A" },
	{ 0x23, "ACCESS" },
	{ 0x24, "B" },
	{ 0x25, "BIG" },
	{ 0x26, "BR" },
	{ 0x27, "CARD" },
	{ 0x28, "DO" },
	{ 0x29, "EM" },
	{ 0x2A, "FIELDSET" },
	{ 0x2B, "GO" },
	{ 0x2C, "HEAD" },
	{ 0x2D, "I" },
	{ 0x2E, "IMG" },
	{ 0x2F, "INPUT" },
	{ 0x30, "META" },
	{ 0x31, "NOOP" },
	{ 0x32, "PREV" },
	{ 0x33, "ONEVENT" },
	{ 0x34, "OPTGROUP" },
	{ 0x35, "OPTION" },
	{ 0x36, "REFRESH" },
	{ 0x37, "SELECT" },
	{ 0x38, "SMALL" },
	{ 0x39, "STRONG" },
	{ 0x3A, "TAB" },
	{ 0x3B, "TEMPLATE" },
	{ 0x3C, "TIMER" },
	{ 0x3D, "U" },
	{ 0x3E, "VAR" },
	{ 0x3F, "WML" },

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

static const wbxml_decoding decode_wmlc_10 = {
    "Wireless Markup Language 1.0",
    "WML 1.0",
    { ext_t_0_wml_10, ext_t_1_wml_10, ext_t_2_wml_10 },
	default_opaque_binary_tag,
	default_opaque_literal_tag,
	default_opaque_binary_attr,
	default_opaque_literal_attr,
    wbxml_wmlc10_global,
    wbxml_wmlc10_tags,
    wbxml_wmlc10_attrStart,
    wbxml_wmlc10_attrValue
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

static const wbxml_decoding decode_wmlc_11 = {
    "Wireless Markup Language 1.1",
    "WML 1.1",
    { ext_t_0_wml_10, ext_t_1_wml_10, ext_t_2_wml_10 },
	default_opaque_binary_tag,
	default_opaque_literal_tag,
	default_opaque_binary_attr,
	default_opaque_literal_attr,
    wbxml_wmlc11_global,
    wbxml_wmlc11_tags,
    wbxml_wmlc11_attrStart,
    wbxml_wmlc11_attrValue
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

static const wbxml_decoding decode_wmlc_12 = {
    "Wireless Markup Language 1.2",
    "WML 1.2",
    { ext_t_0_wml_10, ext_t_1_wml_10, ext_t_2_wml_10 },
	default_opaque_binary_tag,
	default_opaque_literal_tag,
	default_opaque_binary_attr,
	default_opaque_literal_attr,
    wbxml_wmlc12_global,
    wbxml_wmlc12_tags,
    wbxml_wmlc12_attrStart,
    wbxml_wmlc12_attrValue
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

static const wbxml_decoding decode_wmlc_13 = {
    "Wireless Markup Language 1.3",
    "WML 1.3",
    { ext_t_0_wml_10, ext_t_1_wml_10, ext_t_2_wml_10 },
	default_opaque_binary_tag,
	default_opaque_literal_tag,
	default_opaque_binary_attr,
	default_opaque_literal_attr,
    wbxml_wmlc13_global,
    wbxml_wmlc13_tags,
    wbxml_wmlc13_attrStart,
    wbxml_wmlc13_attrValue
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

static const wbxml_decoding decode_sic_10 = {
    "Service Indication 1.0",
    "SI 1.0",
    { NULL, NULL, NULL },
	default_opaque_binary_tag,
	default_opaque_literal_tag,
	sic10_opaque_binary_attr,
	sic10_opaque_literal_attr,
    NULL,
    wbxml_sic10_tags,
    wbxml_sic10_attrStart,
    wbxml_sic10_attrValue
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

static const wbxml_decoding decode_slc_10 = {
    "Service Loading 1.0",
    "SL 1.0",
    { NULL, NULL, NULL },
	default_opaque_binary_tag,
	default_opaque_literal_tag,
	default_opaque_binary_attr,
	default_opaque_literal_attr,
    NULL,
    wbxml_slc10_tags,
    wbxml_slc10_attrStart,
    wbxml_slc10_attrValue
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

static const wbxml_decoding decode_coc_10 = {
    "Cache Operation 1.0",
    "CO 1.0",
    { NULL, NULL, NULL },
	default_opaque_binary_tag,
	default_opaque_literal_tag,
	default_opaque_binary_attr,
	default_opaque_literal_attr,
    NULL,
    wbxml_coc10_tags,
    wbxml_coc10_attrStart,
    wbxml_coc10_attrValue
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

static const wbxml_decoding decode_provc_10 = {
    "WAP Client Provisioning Document 1.0",
    "WAP ProvisioningDoc 1.0",
    { NULL, NULL, NULL },
	default_opaque_binary_tag,
	default_opaque_literal_tag,
	default_opaque_binary_attr,
	default_opaque_literal_attr,
    NULL,
    wbxml_provc10_tags,
    wbxml_provc10_attrStart,
    wbxml_provc10_attrValue
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

static const wbxml_decoding decode_emnc_10 = {
    "E-Mail Notification 1.0",
    "EMN 1.0",
    { NULL, NULL, NULL },
	default_opaque_binary_tag,
	default_opaque_literal_tag,
	emnc10_opaque_binary_attr,
	emnc10_opaque_literal_attr,
    NULL,
    wbxml_emnc10_tags,
    wbxml_emnc10_attrStart,
    wbxml_emnc10_attrValue
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

static const wbxml_decoding decode_syncmlc_10 = {
    "SyncML Representation Protocol 1.0",
    "SyncML 1.0",
    { NULL, NULL, NULL },
	default_opaque_binary_tag,
	default_opaque_literal_tag,
	default_opaque_binary_attr,
	default_opaque_literal_attr,
    NULL,
    wbxml_syncmlc10_tags,
    NULL,
    NULL
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

static const wbxml_decoding decode_syncmlc_11 = {
    "SyncML Representation Protocol 1.1",
    "SyncML 1.1",
    { NULL, NULL, NULL },
	default_opaque_binary_tag,
	default_opaque_literal_tag,
	default_opaque_binary_attr,
	default_opaque_literal_attr,
    NULL,
    wbxml_syncmlc11_tags,
    NULL,
    NULL
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

static const wbxml_decoding decode_channelc_10 = {
    "Wireless Telephony Application (WTA) Channel 1.0",
    "CHANNEL 1.0",
    { NULL, NULL, NULL },
	default_opaque_binary_tag,
	default_opaque_literal_tag,
	default_opaque_binary_attr,
	default_opaque_literal_attr,
    NULL,
    wbxml_channelc10_tags,
    wbxml_channelc10_attrStart,
    NULL
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

static const wbxml_decoding decode_nokiaprovc_70 = {
    "Nokia Client Provisioning 7.0",
    "Nokia Client Provisioning 7.0",
    { NULL, NULL, NULL },
	default_opaque_binary_tag,
	default_opaque_literal_tag,
	default_opaque_binary_attr,
	default_opaque_literal_attr,
    NULL,
    wbxml_nokiaprovc70_tags,
    wbxml_nokiaprovc70_attrStart,
    NULL
};





/* UAProf [WAP-248]
 * 
 * User-Agent Profile (used in profile-diff WSP header)
 ***************************************/

/*****   Global extension tokens   *****/

/*****         Tag tokens          *****/
/* CodePage	0	RDF */
static const value_string  wbxml_uaprof_tags_cp0[] = {
	{0x05, "rdf:RDF"},
	{0x06, "rdf:Description"},
	{0x07, "rdf:Alt"},
	{0x08, "rdf:Bag"},
	{0x09, "rdf:Seq"},
	{0x0A, "rdf:li"},
	{0x0B, "rdf:type"},
	{0x0C, "rdf:value"},
	{0x0D, "rdf:subject"},
	{0x0E, "rdf:predicate"},
	{0x0F, "rdf:object"},

	{ 0x00, NULL }
};

/* CodePage	1	Core Vocabulary */
static const value_string  wbxml_uaprof_tags_cp1[] = {
	{0x06, "rdf:Description"},
	{0x07, "rdf:Alt"},
	{0x08, "rdf:Bag"},
	{0x09, "rdf:Seq"},
	{0x0A, "rdf:li"},
	{0x0B, "rdf:type"},
	{0x0C, "prf:component"},
	{0x0D, "prf:defaults"},
	{0x0E, "prf:BitsPerPixel"},
	{0x0F, "prf:ColorCapable"},
	{0x10, "prf:CPU"},
	{0x11, "prf:ImageCapable"},
	{0x12, "prf:InputCharSet"},
	{0x13, "prf:Keyboard"},
	{0x15, "prf:Model"},
	{0x16, "prf:OutputCharSet"},
	{0x17, "prf:PointingResolution"},
	{0x18, "prf:ScreenSize"},
	{0x19, "prf:ScreenSizeChar"},
	{0x1A, "prf:NumberOfSoftKeys"},
	{0x1B, "prf:SoundOutputCapable"},
	{0x1C, "prf:TextInputCapable"},
	{0x1D, "prf:Vendor"},
	{0x1E, "prf:VoiceInputCapable"},
	{0x1F, "prf:AcceptDownloadableSoftware"},
	{0x20, "prf:AudioInputEncoder"},
	{0x21, "prf:DownloadableSoftwareSupport"},
	{0x22, "prf:JavaEnabled"},
	{0x23, "prf:JVMVersion"},
	{0x24, "prf:MexeClassmark"},
	{0x25, "prf:MexeSpec"},
	{0x26, "prf:OSName"},
	{0x27, "prf:OSVendor"},
	{0x28, "prf:OSVersion"},
	{0x29, "prf:RecipientAppAgent"},
	{0x2A, "prf:SoftwareNumber"},
	{0x2B, "prf:VideoInputEncoder"},
	{0x2C, "prf:CurrentBearerService"},
	{0x2D, "prf:SecuritySupport"},
	{0x2E, "prf:SupportedBearers"},
	{0x2F, "prf:WapDeviceClass"},
	{0x30, "prf:WapPushMsgPriority"}, /* Deprecated */
	{0x31, "prf:WapPushMsgSize"}, /* Deprecated */
	{0x32, "prf:WapVersion"},
	{0x33, "prf:WmlDeckSize"},
	{0x34, "prf:WmlScriptLibraries"},
	{0x35, "prf:WmlScriptVersion"},
	{0x36, "prf:WmlVersion"},
	{0x37, "prf:WtaiLibraries"},
	{0x38, "prf:WtaVersion"},
	{0x39, "prf:PixelAspectRatio"},
	{0x3A, "prf:StandardFontProportional"},
	{0x3B, "prf:WapSupportedApplications"}, /* Deprecated */
	{0x3C, "prf:BluetoothProfile"},
	{0x3D, "prf:MexeClassmarks"},
	{0x3E, "prf:MexeSecureDomains"},

	{ 0x00, NULL }
};

/* CodePage	4	Core Vocabulary (continued) */
static const value_string  wbxml_uaprof_tags_cp4[] = {
	{0x10, "prf:SupportedBluetoothVersion"},
	{0x11, "prf:SupportedPictogramSet"},
	{0x12, "prf:CcppAccept"},
	{0x13, "prf:CcppAccept-Charset"},
	{0x14, "prf:CcppAccept-Encoding"},
	{0x15, "prf:CcppAccept-Language"},

	{ 0x00, NULL }
};

/* CodePage	2	BrowserUA */
static const value_string  wbxml_uaprof_tags_cp2[] = {
	{0x05, "rdf:Description"},
	{0x06, "rdf:Alt"},
	{0x07, "rdf:Bag"},
	{0x08, "rdf:Seq"},
	{0x09, "rdf:li"},
	{0x0A, "rdf:type"},
	{0x0B, "prf:component"},
	{0x0C, "prf:defaults"},
	{0x0D, "prf:BrowserName"},
	{0x0E, "prf:BrowserVersion"},
	{0x0F, "prf:CcppAccept"}, /* Deprecated */
	{0x10, "prf:CcppAccept-Charset"}, /* Deprecated */
	{0x11, "prf:CcppAccept-Encoding"}, /* Deprecated */
	{0x12, "prf:CcppAccept-Language"}, /* Deprecated */
	{0x13, "prf:DownloadableBrowserApps"},
	{0x14, "prf:FramesCapable"},
	{0x15, "prf:HtmlVersion"},
	{0x16, "prf:JavaAppletEnabled"},
	{0x17, "prf:JavaScriptEnabled"},
	{0x18, "prf:JavaScriptVersion"},
	{0x19, "prf:PreferenceForFrames"},
	{0x1A, "prf:TablesCapable"},
	{0x1B, "Prf:XhtmlVersion"},
	{0x1C, "prf:XhtmlModules"},

	{ 0x00, NULL }
};

/* CodePage	3	PushCharacteristics */
static const value_string  wbxml_uaprof_tags_cp3[] = {
	{0x05, "rdf:Description"},
	{0x06, "rdf:Alt"},
	{0x07, "rdf:Bag"},
	{0x08, "rdf:Seq"},
	{0x09, "rdf:li"},
	{0x0A, "rdf:type"},
	{0x0B, "prf:component"},
	{0x0C, "prf:defaults"},
	{0x0D, "prf:Push-Accept"},
	{0x0E, "prf:Push-Accept-Charset"},
	{0x0F, "prf:Push-Accept-Encoding"},
	{0x10, "prf:Push-Accept-Language"},
	{0x11, "prf:Push-Accept-AppID"},
	{0x12, "prf:Push-MsgSize"},
	{0x13, "prf:Push-MaxPushReq"},

	{ 0x00, NULL }
};

/*****    Attribute Start tokens   *****/
/* CodePage	0	RDF */
static const value_string  wbxml_uaprof_attrStart_cp0[] = {
	{0x05, "ID"},
	{0x06, "rdf:about"},
	{0x07, "rdf:aboutEach"},
	{0x08, "rdf:aboutEachPrefix"},
	{0x09, "rdf:bagID"},
	{0x0A, "rdf:type"},
	{0x0B, "rdf:resource"},
	{0x0C, "rdf:parseType='Literal'"},
	{0x0D, "rdf:parseType='Resource'"},
	{0x0E, "xml:lang"},
	{0x0F, "xmlns:prf"},
	{0x10, "xmlns:rdf"},

	{ 0x00, NULL }
};

/* CodePage	1	Core Vocabulary */
static const value_string  wbxml_uaprof_attrStart_cp1[] = {
	{0x05, "rdf:resource"},
	{0x06, "rdf:resource='http://www.wapforum.org/profiles/UAPROF/"
		"ccppschema-20010430#HardwarePlatform'"},
	{0x07, "rdf:resource='http://www.wapforum.org/profiles/UAPROF/"
		"ccppschema-20010430#SoftwarePlatform'"},
	{0x08, "rdf:resource='http://www.wapforum.org/profiles/UAPROF/"
		"ccppschema-20010430#NetworkCharacteristics'"},
	{0x09, "rdf:resource='http://www.wapforum.org/profiles/UAPROF/"
		"ccppschema-20010430#WapCharacteristics'"},
	{0x0A, "rdf:resource='http://www.wapforum.org/profiles/UAPROF/"
		"ccppschema-20010430#BrowserUA'"},
	{0x0B, "rdf:resource='http://www.wapforum.org/profiles/UAPROF/"
		"ccppschema-20010430#PushCharacteristics'"},
	{0x10, "prf:BitsPerPixel"},
	{0x11, "prf:ColorCapable='Yes'"},
	{0x12, "prf:ColorCapable='No'"},
	{0x13, "prf:CPU"},
	{0x14, "prf:ImageCapable='Yes'"},
	{0x15, "prf:ImageCapable='No'"},
	{0x16, "prf:InputCharSet"},
	{0x17, "prf:Keyboard"},
	{0x19, "prf:Model"},
	{0x1A, "prf:OutputCharSet"},
	{0x1B, "prf:PointingResolution"},
	{0x1C, "prf:ScreenSize"},
	{0x1D, "prf:ScreenSizeChar"},
	{0x1E, "prf:NumberOfSoftKeys='Yes'"},
	{0x20, "prf:SoundOutputCapable='Yes'"},
	{0x21, "prf:SoundOutputCapable='No'"},
	{0x22, "prf:TextInputCapable='Yes'"},
	{0x23, "prf:TextInputCapable='No'"},
	{0x24, "prf:Vendor"},
	{0x25, "prf:VoiceInputCapable='Yes'"},
	{0x26, "prf:VoiceInputCapable='No'"},
	{0x27, "prf:PixelAspectRatio"},
	{0x28, "prf:StandardFontProportional='Yes'"},
	{0x29, "prf:StandardFontProportional='No'"},
	{0x30, "prf:AcceptDownloadableSoftware='Yes'"},
	{0x31, "prf:AcceptDownloadableSoftware='No'"},
	{0x32, "prf:AudioInputEncoder"},
	{0x33, "prf:DownloadableSoftwareSupport"},
	{0x35, "prf:JavaEnabled='Yes'"},
	{0x36, "prf:JavaEnabled='No'"},
	{0x37, "prf:JVMVersion"},
	{0x38, "prf:MexeClassmark"},
	{0x39, "prf:MexeSpec"},
	{0x3A, "prf:OSName"},
	{0x3B, "prf:OSVendor"},
	{0x3C, "prf:OSVersion"},
	{0x3D, "prf:RecipientAppAgent"},
	{0x3E, "prf:SoftwareNumber"},
	{0x21, "prf:SoundOutputCapable='No'"},
	{0x22, "prf:TextInputCapable='Yes'"},
	{0x23, "prf:TextInputCapable='No'"},
	{0x24, "prf:Vendor"},
	{0x25, "prf:VoiceInputCapable='Yes'"},
	{0x26, "prf:VoiceInputCapable='No'"},
	{0x27, "prf:PixelAspectRatio"},
	{0x28, "prf:StandardFontProportional='Yes'"},
	{0x29, "prf:StandardFontProportional='No'"},
	{0x30, "prf:AcceptDownloadableSoftware='Yes'"},
	{0x31, "prf:AcceptDownloadableSoftware='No'"},
	{0x32, "prf:AudioInputEncoder"},
	{0x33, "prf:DownloadableSoftwareSupport"},
	{0x35, "prf:JavaEnabled='Yes'"},
	{0x36, "prf:JavaEnabled='No'"},
	{0x37, "prf:JVMVersion"},
	{0x38, "prf:MexeClassmark"},
	{0x39, "prf:MexeSpec"},
	{0x3A, "prf:OSName"},
	{0x3B, "prf:OSVendor"},
	{0x3C, "prf:OSVersion"},
	{0x3D, "prf:RecipientAppAgent"},
	{0x3E, "prf:SoftwareNumber"},
	{0x3F, "prf:VideoInputEncoder"},
	{0x50, "prf:CurrentBearerService"},
	{0x51, "prf:SecuritySupport"},
	{0x52, "prf:SupportedBearers"},
	{0x60, "prf:WapDeviceClass"},
	{0x61, "prf:WapPushMsgPriority"}, /* Deprecated */
	{0x62, "prf:WapPushMsgSize"}, /* Deprecated */
	{0x63, "prf:WapVersion"},
	{0x64, "prf:WmlDeckSize"},
	{0x65, "prf:WmlScriptLibraries"},
	{0x66, "prf:WmlScriptVersion"},
	{0x67, "prf:WmlVersion"},
	{0x68, "prf:WtaiLibraries"},
	{0x69, "prf:WtaVersion"},
	{0x70, "prf:WapSupportedApplications"}, /* Deprecated */
	{0x71, "prf:BluetoothProfile"},
	{0x72, "prf:MexeClassmarks"},
	{0x73, "prf:MexeSecureDomains='YES'"},
	{0x74, "prf:MexeSecureDomains='NO'"},
	{0x75, "prf:SupportedBluetoothVersion"},
	{0x76, "prf:SupportedPictogramSet"},
	{0x77, "prf:CcppAccept"},
	{0x78, "prf:CcppAccept-Charset"},
	{0x79, "prf:CcppAccept-Encoding"},
	{0x7F, "prf:CcppAccept-Language"},

	{ 0x00, NULL }
};

/* CodePage	2	BrowserUA */
static const value_string  wbxml_uaprof_attrStart_cp2[] = {
	{0x05, "prf:CcppAccept"}, /* Deprecated */
	{0x06, "prf:CcppAccept-Charset"}, /* Deprecated */
	{0x07, "prf:CcppAccept-Encoding"}, /* Deprecated */
	{0x08, "prf:CcppAccept-Language"}, /* Deprecated */
	{0x09, "prf:DownloadableBrowserApps"},
	{0x0A, "prf:FramesCapable='Yes'"},
	{0x0B, "prf:FramesCapable='No'"},
	{0x0C, "prf:HtmlVersion='3.2'"},
	{0x0D, "prf:HtmlVersion='4.0'"},
	{0x0E, "prf:JavaAppletEnabled='Yes'"},
	{0x0F, "prf:JavaAppletEnabled='No'"},
	{0x10, "prf:JavaScriptEnabled='Yes'"},
	{0x11, "prf:JavaScriptEnabled='No'"},
	{0x12, "prf:JavaScriptVersion"},
	{0x13, "prf:PreferenceForFrames='Yes'"},
	{0x14, "prf:PreferenceForFrames='No'"},
	{0x15, "prf:TablesCapable='Yes'"},
	{0x16, "prf:TablesCapable='No'"},
	{0x17, "prf:XhtmlVersion"},
	{0x18, "prf:XhtmlModules"},
	{0x19, "prf:BrowserName"},
	{0x1A, "prf:BrowserVersion"},

	{ 0x00, NULL }
};

/* CodePage	3	PushCharacteristics */
static const value_string  wbxml_uaprof_attrStart_cp3[] = {
	{0x05, "prf:Push-Accept"},
	{0x06, "prf:Push-Accept-Charset"},
	{0x07, "prf:Push-Accept-Encoding"},
	{0x08, "prf:Push-Accept-Language"},
	{0x09, "prf:Push-Accept-AppID"},
	{0x0A, "prf:Push-MsgSize"},
	{0x0B, "prf:Push-MaxPushReq"},

	{ 0x00, NULL }
};

/*****    Attribute Value tokens   *****/
/* CodePage	0	RDF */
static const value_string  wbxml_uaprof_attrValue_cp0[] = {
	{0x85, "rdf:Statement"},
	{0x86, "http://"},
	{0x87, "http://www."},
	{0x88, "https://"},
	{0x89, "https://www."},
	{0x8A, "www."},
	{0x8B, ".com/"},
	{0x8C, ".edu/"},
	{0x8D, ".net/"},
	{0x8E, ".org/"},

	{ 0x00, NULL }
};

/* CodePage	1	CoreVocabularyAttrValue */
static const value_string  wbxml_uaprof_attrValue_cp1[] = {
	{0x85, "No"},
	{0x86, "Yes"},

	{ 0x00, NULL }
};

/* CodePage	2	BrowserUAAttrValue */
static const value_string  wbxml_uaprof_attrValue_cp2[] = {
	{0x85, "No"},
	{0x86, "Yes"},

	{ 0x00, NULL }
};

/***** Token code page aggregation *****/
static const value_valuestring wbxml_uaprof_tags[] = {
	{ 0, wbxml_uaprof_tags_cp0 },
	{ 1, wbxml_uaprof_tags_cp1 },
	{ 2, wbxml_uaprof_tags_cp2 },
	{ 3, wbxml_uaprof_tags_cp3 },
	{ 4, wbxml_uaprof_tags_cp4 },
	{ 0, NULL }
};

static const value_valuestring wbxml_uaprof_attrStart[] = {
	{ 0, wbxml_uaprof_attrStart_cp0 },
	{ 1, wbxml_uaprof_attrStart_cp1 },
	{ 2, wbxml_uaprof_attrStart_cp2 },
	{ 3, wbxml_uaprof_attrStart_cp3 },
	{ 0, NULL }
};

static const value_valuestring wbxml_uaprof_attrValue[] = {
	{ 0, wbxml_uaprof_attrValue_cp0 },
	{ 1, wbxml_uaprof_attrValue_cp1 },
	{ 2, wbxml_uaprof_attrValue_cp2 },
	{ 0, NULL }
};

static const wbxml_decoding decode_uaprof_wap_248 = {
    "User-Agent Profile (WAP-174, WAP-248)",
    "UAProf (WAP-174, WAP-248)",
    { NULL, NULL, NULL },
	default_opaque_binary_tag,
	default_opaque_literal_tag,
	default_opaque_binary_attr,
	default_opaque_literal_attr,
    NULL,
    wbxml_uaprof_tags,
    wbxml_uaprof_attrStart,
    wbxml_uaprof_attrValue
};





/* WV-CSP 1.0
 * 
 * Wireless Village Client Server Protocol
 ***************************************/

/*****   Global extension tokens   *****/

/*****         Tag tokens          *****/
/* Common code page (0x00) */
static const value_string wbxml_wv_csp_10_tags_cp0[] = {
	/* 0x00 -- 0x04 GLOBAL */
	{ 0x05, "Acceptance" },
	{ 0x06, "AddList" },
	{ 0x07, "AddNickList" },
	{ 0x08, "Attribute" },
	{ 0x09, "AttributeList" },
	{ 0x0A, "ClientID" },
	{ 0x0B, "Code" },
	{ 0x0C, "ContactList" },
	{ 0x0D, "ContentData" },
	{ 0x0E, "ContentEncoding" },
	{ 0x0F, "ContentSize" },
	{ 0x10, "ContentType" },
	{ 0x11, "DateTime" },
	{ 0x12, "Description" },
	{ 0x13, "DetailedResult" },
	{ 0x14, "EntityList" },
	{ 0x15, "Group" },
	{ 0x16, "GroupID" },
	{ 0x17, "GroupList" },
	{ 0x18, "InUse" },
	{ 0x19, "Logo" },
	{ 0x1A, "MessageCount" },
	{ 0x1B, "MessageID" },
	{ 0x1C, "MessageURI" },
	{ 0x1D, "MSISDN" },
	{ 0x1E, "Name" },
	{ 0x1F, "NickList" },
	{ 0x20, "NickName" },
	{ 0x21, "Poll" },
	{ 0x22, "Presence" },
	{ 0x23, "PresenceSubList" },
	{ 0x24, "PresenceValue" },
	{ 0x25, "Property" },
	{ 0x26, "Qualifier" },
	{ 0x27, "Recipient" },
	{ 0x28, "RemoveList" },
	{ 0x29, "RemoveNickList" },
	{ 0x2A, "Result" },
	{ 0x2B, "ScreenName" },
	{ 0x2C, "Sender" },
	{ 0x2D, "Session" },
	{ 0x2E, "SessionDescriptor" },
	{ 0x2F, "SessionID" },
	{ 0x30, "SessionType" },
	{ 0x31, "Status" },
	{ 0x32, "Transaction" },
	{ 0x33, "TransactionContent" },
	{ 0x34, "TransactionDescriptor" },
	{ 0x35, "TransactionID" },
	{ 0x36, "TransactionMode" },
	{ 0x37, "URL" },
	{ 0x38, "URLList" },
	{ 0x39, "User" },
	{ 0x3A, "UserID" },
	{ 0x3B, "UserList" },
	{ 0x3C, "Validity" },
	{ 0x3D, "Value" },
	{ 0x3E, "WV-CSP-Message" },

	{ 0x00, NULL }
};

/* Access code page (0x01) */
static const value_string wbxml_wv_csp_10_tags_cp1[] = {
	/* 0x00 -- 0x04 GLOBAL */
	{ 0x05, "AllFunctions" },
	{ 0x06, "AllFunctionsRequest" },
	{ 0x07, "CancelInvite-Request" },
	{ 0x08, "CancelInviteUser-Request" },
	{ 0x09, "Capability" },
	{ 0x0A, "CapabilityList" },
	{ 0x0B, "CapabilityRequest" },
	{ 0x0C, "ClientCapability-Request" },
	{ 0x0D, "ClientCapability-Response" },
	{ 0x0E, "DigestBytes" },
	{ 0x0F, "DigestSchema" },
	{ 0x10, "Disconnect" },
	{ 0x11, "Functions" },
	{ 0x12, "GetSPInfo-Request" },
	{ 0x13, "GetSPInfo-Response" },
	{ 0x14, "InviteID" },
	{ 0x15, "InviteNote" },
	{ 0x16, "Invite-Request" },
	{ 0x17, "Invite-Response" },
	{ 0x18, "InviteType" },
	{ 0x19, "InviteUser-Request" },
	{ 0x1A, "InviteUser-Response" },
	{ 0x1B, "KeepAlive-Request" },
	{ 0x1C, "KeepAliveTime" },
	{ 0x1D, "Login-Request" },
	{ 0x1E, "Login-Response" },
	{ 0x1F, "Logout-Request" },
	{ 0x20, "Nonce" },
	{ 0x21, "Password" },
	{ 0x22, "Polling-Request" },
	{ 0x23, "ResponseNote" },
	{ 0x24, "SearchElement" },
	{ 0x25, "SearchFindings" },
	{ 0x26, "SearchID" },
	{ 0x27, "SearchIndex" },
	{ 0x28, "SearchLimit" },
	{ 0x29, "SearchOnlineStatus" },
	{ 0x2A, "SearchPairList" },
	{ 0x2B, "Search-Request" },
	{ 0x2C, "Search-Response" },
	{ 0x2D, "SearchResult" },
	{ 0x2E, "Service-Request" },
	{ 0x2F, "Service-Response" },
	{ 0x30, "SessionCookie" },
	{ 0x31, "StopSearch-Request" },
	{ 0x32, "TimeToLive" },

	{ 0x00, NULL }
};

/* Service code page (0x02) */
static const value_string wbxml_wv_csp_10_tags_cp2[] = {
	/* 0x00 -- 0x04 GLOBAL */
	{ 0x05, "ADDGM" },
	{ 0x06, "AttListFunc" },
	{ 0x07, "BLENT" },
	{ 0x08, "CAAUT" },
	{ 0x09, "CAINV" },
	{ 0x0A, "CALI" },
	{ 0x0B, "CCLI" },
	{ 0x0C, "ContListFunc" },
	{ 0x0D, "CREAG" },
	{ 0x0E, "DALI" },
	{ 0x0F, "DCLI" },
	{ 0x10, "DELGR" },
	{ 0x11, "FundamentalFeat" },
	{ 0x12, "FWMSG" },
	{ 0x13, "GALS" },
	{ 0x14, "GCLI" },
	{ 0x15, "GETGM" },
	{ 0x16, "GETGP" },
	{ 0x17, "GETLM" },
	{ 0x18, "GETM" },
	{ 0x19, "GETPR" },
	{ 0x1A, "GETSPI" },
	{ 0x1B, "GETWL" },
	{ 0x1C, "GLBLU" },
	{ 0x1D, "GRCHN" },
	{ 0x1E, "GroupAuthFunc" },
	{ 0x1F, "GroupFeat" },
	{ 0x20, "GroupMgmtFunc" },
	{ 0x21, "GroupUseFunc" },
	{ 0x22, "IMAuthFunc" },
	{ 0x23, "IMFeat" },
	{ 0x24, "IMReceiveFunc" },
	{ 0x25, "IMSendFunc" },
	{ 0x26, "INVIT" },
	{ 0x27, "InviteFunc" },
	{ 0x28, "MBRAC" },
	{ 0x29, "MCLS" },
	{ 0x2A, "MDELIV" },
	{ 0x2B, "NEWM" },
	{ 0x2C, "NOTIF" },
	{ 0x2D, "PresenceAuthFunc" },
	{ 0x2E, "PresenceDeliverFunc" },
	{ 0x2F, "PresenceFeat" },
	{ 0x30, "REACT" },
	{ 0x31, "REJCM" },
	{ 0x32, "REJEC" },
	{ 0x33, "RMVGM" },
	{ 0x34, "SearchFunc" },
	{ 0x35, "ServiceFunc" },
	{ 0x36, "SETD" },
	{ 0x37, "SETGP" },
	{ 0x38, "SRCH" },
	{ 0x39, "STSRC" },
	{ 0x3A, "SUBGCN" },
	{ 0x3B, "UPDPR" },
	{ 0x3C, "WVCSPFeat" },

	{ 0x00, NULL }
};

/* Client capability code page (0x03) */
static const value_string wbxml_wv_csp_10_tags_cp3[] = {
	/* 0x00 -- 0x04 GLOBAL */
	{ 0x05, "AcceptedCharset" },
	{ 0x06, "AcceptedContentLength" },
	{ 0x07, "AcceptedContentType" },
	{ 0x08, "AcceptedTransferEncoding" },
	{ 0x09, "AnyContent" },
	{ 0x0A, "ClientType" },
	{ 0x0B, "InitialDeliveryMethod" },
	{ 0x0C, "MultiTrans" },
	{ 0x0D, "ParserSize" },
	{ 0x0E, "ServerPollMin" },
	{ 0x0F, "SupportedBearer" },
	{ 0x10, "SupportedCIRMethod" },
	{ 0x11, "TCPAddress" },
	{ 0x12, "TCPPort" },
	{ 0x13, "UDPPort" },

	{ 0x00, NULL }
};

/* Presence primitive code page (0x04) */
static const value_string wbxml_wv_csp_10_tags_cp4[] = {
	/* 0x00 -- 0x04 GLOBAL */
	{ 0x05, "CancelAuth-Request" },
	{ 0x06, "ContactListProperties" },
	{ 0x07, "CreateAttributeList-Request" },
	{ 0x08, "CreateList-Request" },
	{ 0x09, "DefaultAttributeList" },
	{ 0x0A, "DefaultContactList" },
	{ 0x0B, "DefaultList" },
	{ 0x0C, "DeleteAttributeList-Request" },
	{ 0x0D, "DeleteList-Request" },
	{ 0x0E, "GetAttributeList-Request" },
	{ 0x0F, "GetAttributeList-Response" },
	{ 0x10, "GetList-Request" },
	{ 0x11, "GetList-Response" },
	{ 0x12, "GetPresence-Request" },
	{ 0x13, "GetPresence-Response" },
	{ 0x14, "GetWatcherList-Request" },
	{ 0x15, "GetWatcherList-Response" },
	{ 0x16, "ListManage-Request" },
	{ 0x17, "ListManage-Response" },
	{ 0x18, "Presence" },
	{ 0x19, "PresenceAuth-Request" },
	{ 0x1A, "PresenceAuth-Response" },
	{ 0x1B, "PresenceNotification-Request" },
	{ 0x1C, "PresenceValueList" },
	{ 0x1D, "SubscribePresence-Request" },
	{ 0x1E, "UnsubscribePresence-Request" },
	{ 0x1F, "UpdatePresence-Request" },

	{ 0x00, NULL }
};

/* Presence attribute code page (0x05) */
static const value_string wbxml_wv_csp_10_tags_cp5[] = {
	/* 0x00 -- 0x04 GLOBAL */
	{ 0x05, "Accuracy" },
	{ 0x06, "Address" },
	{ 0x07, "AddrPref" },
	{ 0x08, "Alias" },
	{ 0x09, "Altitude" },
	{ 0x0A, "Building" },
	{ 0x0B, "CAddr" },
	{ 0x0C, "City" },
	{ 0x0D, "ClientInfo" },
	{ 0x0E, "ClientProducer" },
	{ 0x0F, "ClientType" },
	{ 0x10, "ClientVersion" },
	{ 0x11, "CommC" },
	{ 0x12, "CommCap" },
	{ 0x13, "ContactInfo" },
	{ 0x14, "ContainedvCard" },
	{ 0x15, "Country" },
	{ 0x16, "Crossing1" },
	{ 0x17, "Crossing2" },
	{ 0x18, "DevManufacturer" },
	{ 0x19, "DirectContent" },
	{ 0x1A, "FreeTextLocation" },
	{ 0x1B, "GeoLocation" },
	{ 0x1C, "Language" },
	{ 0x1D, "Latitude" },
	{ 0x1E, "Longitude" },
	{ 0x1F, "Model" },
	{ 0x20, "NamedArea" },
	{ 0x21, "OnlineStatus" },
	{ 0x22, "PLMN" },
	{ 0x23, "PrefC" },
	{ 0x24, "PreferredContacts" },
	{ 0x25, "PreferredLanguage" },
	{ 0x26, "ReferredContent" },
	{ 0x27, "ReferredvCard" },
	{ 0x28, "Registration" },
	{ 0x29, "StatusContent" },
	{ 0x2A, "StatusMood" },
	{ 0x2B, "StatusText" },
	{ 0x2C, "Street" },
	{ 0x2D, "TimeZone" },
	{ 0x2E, "UserAvailability" },

	{ 0x00, NULL }
};

/* Messaging code page (0x06) */
static const value_string wbxml_wv_csp_10_tags_cp6[] = {
	/* 0x00 -- 0x04 GLOBAL */
	{ 0x05, "BlockList" },
	{ 0x06, "BlockUser-Request" },
	{ 0x07, "DeliveryMethod" },
	{ 0x08, "DeliveryReport" },
	{ 0x09, "DeliveryReport-Request" },
	{ 0x0A, "ForwardMessage-Request" },
	{ 0x0B, "GetBlockedList-Request" },
	{ 0x0C, "GetBlockedList-Response" },
	{ 0x0D, "GetMessageList-Request" },
	{ 0x0E, "GetMessageList-Response" },
	{ 0x0F, "GetMessage-Request" },
	{ 0x10, "GetMessage-Response" },
	{ 0x11, "GrantList" },
	{ 0x12, "MessageDelivered" },
	{ 0x13, "MessageInfo" },
	{ 0x14, "MessageNotification" },
	{ 0x15, "NewMessage" },
	{ 0x16, "RejectMessage-Request" },
	{ 0x17, "SendMessage-Request" },
	{ 0x18, "SendMessage-Response" },
	{ 0x19, "SetDeliveryMethod-Request" },

	{ 0x00, NULL }
};

/* Group code page (0x07) */
static const value_string wbxml_wv_csp_10_tags_cp7[] = {
	/* 0x00 -- 0x04 GLOBAL */
	{ 0x05, "AddGroupMembers-Request" },
	{ 0x06, "Admin" },
	{ 0x07, "CreateGroup-Request" },
	{ 0x08, "DeleteGroup-Request" },
	{ 0x09, "GetGroupMembers-Request" },
	{ 0x0A, "GetGroupMembers-Response" },
	{ 0x0B, "GetGroupProps-Request" },
	{ 0x0C, "GetGroupProps-Response" },
	{ 0x0D, "GroupChangeNotice" },
	{ 0x0E, "GroupProperties" },
	{ 0x0F, "Joined" },
	{ 0x10, "JoinedRequest" },
	{ 0x11, "JoinGroup-Request" },
	{ 0x12, "JoinGroup-Response" },
	{ 0x13, "LeaveGroup-Request" },
	{ 0x14, "LeaveGroup-Response" },
	{ 0x15, "Left" },
	{ 0x16, "MemberAccess-Request" },
	{ 0x17, "Mod" },
	{ 0x18, "OwnProperties" },
	{ 0x19, "RejectList-Request" },
	{ 0x1A, "RejectList-Response" },
	{ 0x1B, "RemoveGroupMembers-Request" },
	{ 0x1C, "SetGroupProps-Request" },
	{ 0x1D, "SubscribeGroupNotice-Request" },
	{ 0x1E, "SubscribeGroupNotice-Response" },
	{ 0x1F, "Users" },
	{ 0x20, "WelcomeNote" },

	{ 0x00, NULL }
};

/*
 * Attribute start tokens
 */
/* common code page (0x00) */
static const value_string wbxml_wv_csp_10_attrStart_cp0[] = {
	/* 0x00 -- 0x04 GLOBAL */
	{ 0x05, "xmlns='http://www.wireless-village.org/CSP'" },
	{ 0x06, "xmlns='http://www.wireless-village.org/PA'" },
	{ 0x07, "xmlns='http://www.wireless-village.org/TRC'" },

	{ 0x00, NULL }
};

/*
 * Attribute value tokens
 */
/* Common value tokens (0x00) */
static const value_string wbxml_wv_csp_10_attrValue_cp0[] = {
	/* 0x80 -- 0x84 GLOBAL */
	{ 0x85, "AccessType" },
	{ 0x86, "ActiveUsers" },
	{ 0x87, "Admin" },
	{ 0x88, "application/" },
	{ 0x89, "application/vnd.wap.mms-message" },
	{ 0x8A, "application/x-sms" },
	{ 0x8B, "BASE64" },
	{ 0x8C, "Closed" },
	{ 0x8D, "Default" },
	{ 0x8E, "DisplayName" },
	{ 0x8F, "False (No)" },
	{ 0x90, "Get" },
	{ 0x91, "Group (GR)" },
	{ 0x92, "http://" },
	{ 0x93, "https://" },
	{ 0x94, "image/" },
	{ 0x95, "Inband" },
	{ 0x96, "Instant Messaging (IM)" },
	{ 0x97, "MaxActiveUsers" },
	{ 0x98, "Mod" },
	{ 0x99, "Name" },
	{ 0x9A, "None" },
	{ 0x9B, "Notify/Get" },
	{ 0x9C, "Open" },
	{ 0x9D, "Outband" },
	{ 0x9E, "Presence (PR)" },
	{ 0x9F, "Private" },
	{ 0xA0, "PrivateMessaging" },
	{ 0xA1, "PrivilegeLevel" },
	{ 0xA2, "Public" },
	{ 0xA3, "Push" },
	{ 0xA4, "Request" },
	{ 0xA5, "Response" },
	{ 0xA6, "ScreenName" },
	{ 0xA7, "Searchable" },
	{ 0xA8, "Set" },
	{ 0xA9, "Shared Content (SC)" },
	{ 0xAA, "text/" },
	{ 0xAB, "text/plain" },
	{ 0xAC, "text/x-vCalendar" },
	{ 0xAD, "text/x-vCard" },
	{ 0xAE, "Topic" },
	{ 0xAF, "True (Yes)" },
	{ 0xB0, "Type" },
	{ 0xB1, "Unset" },
	{ 0xB2, "User (US)" },
	{ 0xB3, "www.wireless-village.org" },

	{ 0x00, NULL }
};

/* Access value tokens (0x01) */
static const value_string wbxml_wv_csp_10_attrValue_cp1[] = {
	/* 0x80 -- 0x84 GLOBAL */
	{ 0x85, "GROUP_ID" },
	{ 0x86, "GROUP_NAME" },
	{ 0x87, "GROUP_TOPIC" },
	{ 0x88, "GROUP_USER_ID_JOINED" },
	{ 0x89, "HTTP" },
	{ 0x8A, "SMS" },
	{ 0x8B, "STCP" },
	{ 0x8C, "SUDP" },
	{ 0x8D, "USER_ALIAS" },
	{ 0x8E, "USER_EMAIL_ADDRESS" },
	{ 0x8F, "USER_FIRST_NAME" },
	{ 0x90, "USER_ID" },
	{ 0x91, "USER_LAST_NAME" },
	{ 0x92, "USER_MOBILE_NUMBER" },
	{ 0x93, "WAPSMS" },
	{ 0x94, "WAPUDP" },
	{ 0x95, "WSP" },

	{ 0x00, NULL }
};

/* Presence value tokens (0x05) */
static const value_string wbxml_wv_csp_10_attrValue_cp5[] = {
	/* 0x80 -- 0x84 GLOBAL */
	{ 0x85, "ANGRY" },
	{ 0x86, "ANXIOUS" },
	{ 0x87, "ASHAMED" },
	{ 0x88, "AUDIO_CALL" },
	{ 0x89, "AVAILABLE" },
	{ 0x8A, "BORED" },
	{ 0x8B, "CALL" },
	{ 0x8C, "CLI" },
	{ 0x8D, "COMPUTER" },
	{ 0x8E, "DISCREET" },
	{ 0x8F, "EMAIL" },
	{ 0x90, "EXCITED" },
	{ 0x91, "HAPPY" },
	{ 0x92, "IM" },
	{ 0x93, "IM_OFFLINE" },
	{ 0x94, "IM_ONLINE" },
	{ 0x95, "IN_LOVE" },
	{ 0x96, "INVINCIBLE" },
	{ 0x97, "JEALOUS" },
	{ 0x98, "MMS" },
	{ 0x99, "MOBILE_PHONE" },
	{ 0x9A, "NOT_AVAILABLE" },
	{ 0x9B, "OTHER" },
	{ 0x9C, "PDA" },
	{ 0x9D, "SAD" },
	{ 0x9E, "SLEEPY" },
	{ 0x9F, "SMS" },
	{ 0xA0, "VIDEO_CALL" },
	{ 0xA1, "VIDEO_STREAM" },

	{ 0x00, NULL }
};


/***** Token code page aggregation *****/
static const value_valuestring wbxml_wv_csp_10_tags[] = {
	{ 0, wbxml_wv_csp_10_tags_cp0 },
	{ 1, wbxml_wv_csp_10_tags_cp1 },
	{ 2, wbxml_wv_csp_10_tags_cp2 },
	{ 3, wbxml_wv_csp_10_tags_cp3 },
	{ 4, wbxml_wv_csp_10_tags_cp4 },
	{ 5, wbxml_wv_csp_10_tags_cp5 },
	{ 6, wbxml_wv_csp_10_tags_cp6 },
	{ 7, wbxml_wv_csp_10_tags_cp7 },
	{ 0, NULL }
};

static const value_valuestring wbxml_wv_csp_10_attrStart[] = {
	{ 0, wbxml_wv_csp_10_attrStart_cp0 },
	{ 0, NULL }
};

static const value_valuestring wbxml_wv_csp_10_attrValue[] = {
	{ 0, wbxml_wv_csp_10_attrValue_cp0 },
	{ 1, wbxml_wv_csp_10_attrValue_cp1 },
	{ 5, wbxml_wv_csp_10_attrValue_cp5 },
	{ 0, NULL }
};

static const wbxml_decoding decode_wv_cspc_10 = {
    "Wireless-Village Client-Server Protocol 1.0",
    "WV-CSP 1.0",
    { NULL, NULL, NULL },
	wv_csp10_opaque_binary_tag,
	default_opaque_literal_tag,
	default_opaque_binary_attr,
	default_opaque_literal_attr,
    NULL,
    wbxml_wv_csp_10_tags,
    wbxml_wv_csp_10_attrStart,
    wbxml_wv_csp_10_attrValue
};





/* WV-CSP 1.1
 * 
 * Wireless Village Client Server Protocol
 ***************************************/

/*****   Global extension tokens   *****/
static const value_string wbxml_wv_csp_11_global_cp0[] = {
	{ 0x80, "Common Value" }, /* EXT_T_0 */

	{ 0x00, NULL }
};

/*****         Tag tokens          *****/
/* Common code page */
static const value_string wbxml_wv_csp_11_tags_cp0[] = {
	/* 0x00 -- 0x04 GLOBAL */
	{ 0x05, "Acceptance" },
	{ 0x06, "AddList" },
	{ 0x07, "AddNickList" },
	{ 0x08, "SName" },		/* Was: Attribute */
	{ 0x09, "WV-CSP-Message" },	/* Was: AttributeList */
	{ 0x0A, "ClientID" },
	{ 0x0B, "Code" },
	{ 0x0C, "ContactList" },
	{ 0x0D, "ContentData" },
	{ 0x0E, "ContentEncoding" },
	{ 0x0F, "ContentSize" },
	{ 0x10, "ContentType" },
	{ 0x11, "DateTime" },
	{ 0x12, "Description" },
	{ 0x13, "DetailedResult" },
	{ 0x14, "EntityList" },
	{ 0x15, "Group" },
	{ 0x16, "GroupID" },
	{ 0x17, "GroupList" },
	{ 0x18, "InUse" },
	{ 0x19, "Logo" },
	{ 0x1A, "MessageCount" },
	{ 0x1B, "MessageID" },
	{ 0x1C, "MessageURI" },
	{ 0x1D, "MSISDN" },
	{ 0x1E, "Name" },
	{ 0x1F, "NickList" },
	{ 0x20, "NickName" },
	{ 0x21, "Poll" },
	{ 0x22, "Presence" },
	{ 0x23, "PresenceSubList" },
	{ 0x24, "PresenceValue" },
	{ 0x25, "Property" },
	{ 0x26, "Qualifier" },
	{ 0x27, "Recipient" },
	{ 0x28, "RemoveList" },
	{ 0x29, "RemoveNickList" },
	{ 0x2A, "Result" },
	{ 0x2B, "ScreenName" },
	{ 0x2C, "Sender" },
	{ 0x2D, "Session" },
	{ 0x2E, "SessionDescriptor" },
	{ 0x2F, "SessionID" },
	{ 0x30, "SessionType" },
	{ 0x31, "Status" },
	{ 0x32, "Transaction" },
	{ 0x33, "TransactionContent" },
	{ 0x34, "TransactionDescriptor" },
	{ 0x35, "TransactionID" },
	{ 0x36, "TransactionMode" },
	{ 0x37, "URL" },
	{ 0x38, "URLList" },
	{ 0x39, "User" },
	{ 0x3A, "UserID" },
	{ 0x3B, "UserList" },
	{ 0x3C, "Validity" },
	{ 0x3D, "Value" },
	/* 0x3E - Removed: WV-CSP-Message */

	{ 0x00, NULL }
};

/* Access code page */
static const value_string wbxml_wv_csp_11_tags_cp1[] = {
	/* 0x00 -- 0x04 GLOBAL */
	{ 0x05, "AllFunctions" },
	{ 0x06, "AllFunctionsRequest" },
	{ 0x07, "CancelInvite-Request" },
	{ 0x08, "CancelInviteUser-Request" },
	{ 0x09, "Capability" },
	{ 0x0A, "CapabilityList" },
	{ 0x0B, "CapabilityRequest" },
	{ 0x0C, "ClientCapability-Request" },
	{ 0x0D, "ClientCapability-Response" },
	{ 0x0E, "DigestBytes" },
	{ 0x0F, "DigestSchema" },
	{ 0x10, "Disconnect" },
	{ 0x11, "Functions" },
	{ 0x12, "GetSPInfo-Request" },
	{ 0x13, "GetSPInfo-Response" },
	{ 0x14, "InviteID" },
	{ 0x15, "InviteNote" },
	{ 0x16, "Invite-Request" },
	{ 0x17, "Invite-Response" },
	{ 0x18, "InviteType" },
	{ 0x19, "InviteUser-Request" },
	{ 0x1A, "InviteUser-Response" },
	{ 0x1B, "KeepAlive-Request" },
	{ 0x1C, "KeepAliveTime" },
	{ 0x1D, "Login-Request" },
	{ 0x1E, "Login-Response" },
	{ 0x1F, "Logout-Request" },
	{ 0x20, "Nonce" },
	{ 0x21, "Password" },
	{ 0x22, "Polling-Request" },
	{ 0x23, "ResponseNote" },
	{ 0x24, "SearchElement" },
	{ 0x25, "SearchFindings" },
	{ 0x26, "SearchID" },
	{ 0x27, "SearchIndex" },
	{ 0x28, "SearchLimit" },
	{ 0x29, "KeepAlive-Response" },	/* Was: SearchOnlineStatus */
	{ 0x2A, "SearchPairList" },
	{ 0x2B, "Search-Request" },
	{ 0x2C, "Search-Response" },
	{ 0x2D, "SearchResult" },
	{ 0x2E, "Service-Request" },
	{ 0x2F, "Service-Response" },
	{ 0x30, "SessionCookie" },
	{ 0x31, "StopSearch-Request" },
	{ 0x32, "TimeToLive" },
	/* New in WV-CSP 1.1 */
	{ 0x33, "SearchString" },
	{ 0x34, "CompletionFlag" },

	{ 0x00, NULL }
};

/* Service code page */
/* Same as cp2 of WV-CSP 1.0 */
#define wbxml_wv_csp_11_tags_cp2 wbxml_wv_csp_10_tags_cp2

/* Client capability code page */
static const value_string wbxml_wv_csp_11_tags_cp3[] = {
	/* 0x00 -- 0x04 GLOBAL */
	{ 0x05, "AcceptedCharset" },
	{ 0x06, "AcceptedContentLength" },
	{ 0x07, "AcceptedContentType" },
	{ 0x08, "AcceptedTransferEncoding" },
	{ 0x09, "AnyContent" },
	{ 0x0A, "DefaultLanguage" },	/* Was: ClientType */
	{ 0x0B, "InitialDeliveryMethod" },
	{ 0x0C, "MultiTrans" },
	{ 0x0D, "ParserSize" },
	{ 0x0E, "ServerPollMin" },
	{ 0x0F, "SupportedBearer" },
	{ 0x10, "SupportedCIRMethod" },
	{ 0x11, "TCPAddress" },
	{ 0x12, "TCPPort" },
	{ 0x13, "UDPPort" },

	{ 0x00, NULL }
};

/* Presence primitive code page */
static const value_string wbxml_wv_csp_11_tags_cp4[] = {
	/* 0x00 -- 0x04 GLOBAL */
	{ 0x05, "CancelAuth-Request" },
	{ 0x06, "ContactListProperties" },
	{ 0x07, "CreateAttributeList-Request" },
	{ 0x08, "CreateList-Request" },
	{ 0x09, "DefaultAttributeList" },
	{ 0x0A, "DefaultContactList" },
	{ 0x0B, "DefaultList" },
	{ 0x0C, "DeleteAttributeList-Request" },
	{ 0x0D, "DeleteList-Request" },
	{ 0x0E, "GetAttributeList-Request" },
	{ 0x0F, "GetAttributeList-Response" },
	{ 0x10, "GetList-Request" },
	{ 0x11, "GetList-Response" },
	{ 0x12, "GetPresence-Request" },
	{ 0x13, "GetPresence-Response" },
	{ 0x14, "GetWatcherList-Request" },
	{ 0x15, "GetWatcherList-Response" },
	{ 0x16, "ListManage-Request" },
	{ 0x17, "ListManage-Response" },
	{ 0x18, "UnsubscribePresence-Request" },	/* Was: Presence */
	{ 0x19, "PresenceAuth-Request" },
	{ 0x1A, "PresenceAuth-User" },		/* Was: PresenceAuth-Response */
	{ 0x1B, "PresenceNotification-Request" },
	{ 0x1C, "UpdatePresence-Request" },	/* Was: PresenceValueList */
	{ 0x1D, "SubscribePresence-Request" },
	/* 0x1E - Removed: UnsubscribePresence-Request */
	/* 0x1F - Removed: UpdatePresence-Request */

	{ 0x00, NULL }
};

/* Presence attribute code page */
static const value_string wbxml_wv_csp_11_tags_cp5[] = {
	/* 0x00 -- 0x04 GLOBAL */
	{ 0x05, "Accuracy" },
	{ 0x06, "Address" },
	{ 0x07, "AddrPref" },
	{ 0x08, "Alias" },
	{ 0x09, "Altitude" },
	{ 0x0A, "Building" },
	{ 0x0B, "Caddr" },
	{ 0x0C, "City" },
	{ 0x0D, "ClientInfo" },
	{ 0x0E, "ClientProducer" },
	{ 0x0F, "ClientType" },
	{ 0x10, "ClientVersion" },
	{ 0x11, "CommC" },
	{ 0x12, "CommCap" },
	{ 0x13, "ContactInfo" },
	{ 0x14, "ContainedvCard" },
	{ 0x15, "Country" },
	{ 0x16, "Crossing1" },
	{ 0x17, "Crossing2" },
	{ 0x18, "DevManufacturer" },
	{ 0x19, "DirectContent" },
	{ 0x1A, "FreeTextLocation" },
	{ 0x1B, "GeoLocation" },
	{ 0x1C, "Language" },
	{ 0x1D, "Latitude" },
	{ 0x1E, "Longitude" },
	{ 0x1F, "Model" },
	{ 0x20, "NamedArea" },
	{ 0x21, "OnlineStatus" },
	{ 0x22, "PLMN" },
	{ 0x23, "PrefC" },
	{ 0x24, "PreferredContacts" },
	{ 0x25, "PreferredLanguage" },
	{ 0x26, "ReferredContent" },
	{ 0x27, "ReferredvCard" },
	{ 0x28, "Registration" },
	{ 0x29, "StatusContent" },
	{ 0x2A, "StatusMood" },
	{ 0x2B, "StatusText" },
	{ 0x2C, "Street" },
	{ 0x2D, "TimeZone" },
	{ 0x2E, "UserAvailability" },
	/* New in WV-CSP 1.1 */
	{ 0x2F, "Cap" },
	{ 0x30, "Cname" },
	{ 0x31, "Contact" },
	{ 0x32, "Cpriority" },
	{ 0x33, "Cstatus" },
	{ 0x34, "Note" },
	{ 0x35, "Zone" },

	{ 0x00, NULL }
};

/* Messaging code page */
static const value_string wbxml_wv_csp_11_tags_cp6[] = {
	/* 0x00 -- 0x04 GLOBAL */
	{ 0x05, "BlockList" },
	{ 0x06, "BlockUser-Request" },
	{ 0x07, "DeliveryMethod" },
	{ 0x08, "DeliveryReport" },
	{ 0x09, "DeliveryReport-Request" },
	{ 0x0A, "ForwardMessage-Request" },
	{ 0x0B, "GetBlockedList-Request" },
	{ 0x0C, "GetBlockedList-Response" },
	{ 0x0D, "GetMessageList-Request" },
	{ 0x0E, "GetMessageList-Response" },
	{ 0x0F, "GetMessage-Request" },
	{ 0x10, "GetMessage-Response" },
	{ 0x11, "GrantList" },
	{ 0x12, "MessageDelivered" },
	{ 0x13, "MessageInfo" },
	{ 0x14, "MessageNotification" },
	{ 0x15, "NewMessage" },
	{ 0x16, "RejectMessage-Request" },
	{ 0x17, "SendMessage-Request" },
	{ 0x18, "SendMessage-Response" },
	{ 0x19, "SetDeliveryMethod-Request" },
	/* New in WV-CSP 1.1 */
	{ 0x1A, "DeliveryTime" },

	{ 0x00, NULL }
};

/* Group code page */
static const value_string wbxml_wv_csp_11_tags_cp7[] = {
	/* 0x00 -- 0x04 GLOBAL */
	{ 0x05, "AddGroupMembers-Request" },
	{ 0x06, "Admin" },
	{ 0x07, "CreateGroup-Request" },
	{ 0x08, "DeleteGroup-Request" },
	{ 0x09, "GetGroupMembers-Request" },
	{ 0x0A, "GetGroupMembers-Response" },
	{ 0x0B, "GetGroupProps-Request" },
	{ 0x0C, "GetGroupProps-Response" },
	{ 0x0D, "GroupChangeNotice" },
	{ 0x0E, "GroupProperties" },
	{ 0x0F, "Joined" },
	{ 0x10, "JoinedRequest" },
	{ 0x11, "JoinGroup-Request" },
	{ 0x12, "JoinGroup-Response" },
	{ 0x13, "LeaveGroup-Request" },
	{ 0x14, "LeaveGroup-Response" },
	{ 0x15, "Left" },
	{ 0x16, "MemberAccess-Request" },
	{ 0x17, "Mod" },
	{ 0x18, "OwnProperties" },
	{ 0x19, "RejectList-Request" },
	{ 0x1A, "RejectList-Response" },
	{ 0x1B, "RemoveGroupMembers-Request" },
	{ 0x1C, "SetGroupProps-Request" },
	{ 0x1D, "SubscribeGroupNotice-Request" },
	{ 0x1E, "SubscribeGroupNotice-Response" },
	{ 0x1F, "Users" },
	{ 0x20, "WelcomeNote" },
	/* New in WV-CSP 1.1 */
	{ 0x21, "JoinGroup" },
	{ 0x22, "SubscribeNotification" },
	{ 0x23, "SubscribeType" },

	{ 0x00, NULL }
};

/*****    Attribute Start tokens   *****/
/* Common code page */
/* Same as cp0 of WV-CSP 1.0 */
#define wbxml_wv_csp_11_attrStart_cp0 wbxml_wv_csp_10_attrStart_cp0

/*****    Attribute Value tokens   *****/
/*
 * Element value tokens
 *
 * NOTE - WV-CSP uses the EXT_T_0 token in a peculiar way: the mb_u_int32
 * does *not* reference an offset in the string table, but it refers to
 * the index in the following value_string.
 * 
 * Please note that:
 *  - Values 'T' and 'F' are Boolean values representing "True" and "False"
 *    (or "Yes" and "No" in some circumstances) respectively.
 *  - Values 'GR', 'IM', 'PR', 'SC', 'GM' and 'US' are enumerated values
 *    representing "Group", "Instant Messaging", "Presence", "Shared Content",
 *    "Group membership" and "User" respectively.
 *  - Values 'G', 'S' and 'U' are enumerated values representing "Get", "Set"
 *    and "Unset" respectively.
 *  - Values 'N' and 'P' are enumerated values representing "Notify/Get" and
 *    "Push" respectively.
 *
 * I repeat: this is NOT a attrValue[] array hence it is not called
 * wbxml_wv_XXX but vals_wv_XXX.
 *
 * Result: the attribute value token definitions from WV-CSP 1.0 are dropped.
 */
static const value_string vals_wv_csp_11_element_value_tokens[] = {
	/*
	 * Common value tokens
	 */
	{ 0x00, "AccessType" },
	{ 0x01, "ActiveUsers" },
	{ 0x02, "Admin" },
	{ 0x03, "application/" },
	{ 0x04, "application/vnd.wap.mms-message" },
	{ 0x05, "application/x-sms" },
	{ 0x06, "AutoJoin" },
	{ 0x07, "BASE64" },
	{ 0x08, "Closed" },
	{ 0x09, "Default" },
	{ 0x0A, "DisplayName" },
	{ 0x0B, "F" },
	{ 0x0C, "G" },
	{ 0x0D, "GR" },
	{ 0x0E, "http://" },
	{ 0x0F, "https://" },
	{ 0x10, "image/" },
	{ 0x11, "Inband" },
	{ 0x12, "IM" },
	{ 0x13, "MaxActiveUsers" },
	{ 0x14, "Mod" },
	{ 0x15, "Name" },
	{ 0x16, "None" },
	{ 0x17, "N" },
	{ 0x18, "Open" },
	{ 0x19, "Outband" },
	{ 0x1A, "PR" },
	{ 0x1B, "Private" },
	{ 0x1C, "PrivateMessaging" },
	{ 0x1D, "PrivilegeLevel" },
	{ 0x1E, "Public" },
	{ 0x1F, "P" },
	{ 0x20, "Request" },
	{ 0x21, "Response" },
	{ 0x22, "Restricted" },
	{ 0x23, "ScreenName" },
	{ 0x24, "Searchable" },
	{ 0x25, "S" },
	{ 0x26, "SC" },
	{ 0x27, "text/" },
	{ 0x28, "text/plain" },
	{ 0x29, "text/x-vCalendar" },
	{ 0x2A, "text/x-vCard" },
	{ 0x2B, "Topic" },
	{ 0x2C, "T" },
	{ 0x2D, "Type" },
	{ 0x2E, "U" },
	{ 0x2F, "US" },
	{ 0x30, "www.wireless-village.org" },
	/*
	 * Access value tokens
	 */
	{ 0x3D, "GROUP_ID" },
	{ 0x3E, "GROUP_NAME" },
	{ 0x3F, "GROUP_TOPIC" },
	{ 0x40, "GROUP_USER_ID_JOINED" },
	{ 0x41, "GROUP_USER_ID_OWNER" },
	{ 0x42, "HTTP" },
	{ 0x43, "SMS" },
	{ 0x44, "STCP" },
	{ 0x45, "SUDP" },
	{ 0x46, "USER_ALIAS" },
	{ 0x47, "USER_EMAIL_ADDRESS" },
	{ 0x48, "USER_FIRST_NAME" },
	{ 0x49, "USER_ID" },
	{ 0x4A, "USER_LAST_NAME" },
	{ 0x4B, "USER_MOBILE_NUMBER" },
	{ 0x4C, "USER_ONLINE_STATUS" },
	{ 0x4D, "WAPSMS" },
	{ 0x4E, "WAPUDP" },
	{ 0x4F, "WSP" },
	/*
	 * Presence value tokens
	 */
	{ 0x5B, "ANGRY" },
	{ 0x5C, "ANXIOUS" },
	{ 0x5D, "ASHAMED" },
	{ 0x5E, "AUDIO_CALL" },
	{ 0x5F, "AVAILABLE" },
	{ 0x60, "BORED" },
	{ 0x61, "CALL" },
	{ 0x62, "CLI" },
	{ 0x63, "COMPUTER" },
	{ 0x64, "DISCREET" },
	{ 0x65, "EMAIL" },
	{ 0x66, "EXCITED" },
	{ 0x67, "HAPPY" },
	{ 0x68, "IM" },
	{ 0x69, "IM_OFFLINE" },
	{ 0x6A, "IM_ONLINE" },
	{ 0x6B, "IN_LOVE" },
	{ 0x6C, "INVINCIBLE" },
	{ 0x6D, "JEALOUS" },
	{ 0x6E, "MMS" },
	{ 0x6F, "MOBILE_PHONE" },
	{ 0x70, "NOT_AVAILABLE" },
	{ 0x71, "OTHER" },
	{ 0x72, "PDA" },
	{ 0x73, "SAD" },
	{ 0x74, "SLEEPY" },
	{ 0x75, "SMS" },
	{ 0x76, "VIDEO_CALL" },
	{ 0x77, "VIDEO_STREAM" },

	{ 0x00, NULL }
};


/***** Token code page aggregation *****/

static char *
ext_t_0_wv_cspc_11(tvbuff_t *tvb _U_, guint32 value, guint32 str_tbl _U_)
{
    char *str = g_strdup_printf("Common Value: '%s'",
	    val_to_str(value, vals_wv_csp_11_element_value_tokens,
		"<Unknown WV-CSP 1.1 Common Value token 0x%X>"));
    return str;
}

static const value_valuestring wbxml_wv_csp_11_global[] = {
	{ 0, wbxml_wv_csp_11_global_cp0 },
	{ 0, NULL }
};

static const value_valuestring wbxml_wv_csp_11_tags[] = {
	{ 0, wbxml_wv_csp_11_tags_cp0 },
	{ 1, wbxml_wv_csp_11_tags_cp1 },
	{ 2, wbxml_wv_csp_11_tags_cp2 },
	{ 3, wbxml_wv_csp_11_tags_cp3 },
	{ 4, wbxml_wv_csp_11_tags_cp4 },
	{ 5, wbxml_wv_csp_11_tags_cp5 },
	{ 6, wbxml_wv_csp_11_tags_cp6 },
	{ 7, wbxml_wv_csp_11_tags_cp7 },
	{ 0, NULL }
};

static const value_valuestring wbxml_wv_csp_11_attrStart[] = {
	{ 0, wbxml_wv_csp_11_attrStart_cp0 },
	{ 0, NULL }
};

static const wbxml_decoding decode_wv_cspc_11 = {
    "Wireless-Village Client-Server Protocol 1.1",
    "WV-CSP 1.1",
    { ext_t_0_wv_cspc_11, NULL, NULL },
	wv_csp11_opaque_binary_tag,
	default_opaque_literal_tag,
	default_opaque_binary_attr,
	default_opaque_literal_attr,
    wbxml_wv_csp_11_global,
    wbxml_wv_csp_11_tags,
    wbxml_wv_csp_11_attrStart,
    NULL
};





/* WV-CSP 1.2
 * 
 * Wireless Village Client Server Protocol
 ***************************************/
#ifdef Remove_this_comment_when_WV_CSP_will_be_an_approved_spec

/*****   Global extension tokens   *****/
/* Same as WV-CSP 1.1 */

/*****         Tag tokens          *****/
/* Common code page */
/* Same as cp0 of WV-CSP 1.1 */
#define wbxml_wv_csp_12_tags_cp0 wbxml_wv_csp_11_tags_cp0
/* Note that the table continues in code page 0x09 */

/* Access code page (0x01) */
static const value_string wbxml_wv_csp_12_tags_cp1[] = {
	/* 0x00 -- 0x04 GLOBAL */
	{ 0x05, "AllFunctions" },
	{ 0x06, "AllFunctionsRequest" },
	{ 0x07, "CancelInvite-Request" },
	{ 0x08, "CancelInviteUser-Request" },
	{ 0x09, "Capability" },
	{ 0x0A, "CapabilityList" },
	{ 0x0B, "CapabilityRequest" },
	{ 0x0C, "ClientCapability-Request" },
	{ 0x0D, "ClientCapability-Response" },
	{ 0x0E, "DigestBytes" },
	{ 0x0F, "DigestSchema" },
	{ 0x10, "Disconnect" },
	{ 0x11, "Functions" },
	{ 0x12, "GetSPInfo-Request" },
	{ 0x13, "GetSPInfo-Response" },
	{ 0x14, "InviteID" },
	{ 0x15, "InviteNote" },
	{ 0x16, "Invite-Request" },
	{ 0x17, "Invite-Response" },
	{ 0x18, "InviteType" },
	{ 0x19, "InviteUser-Request" },
	{ 0x1A, "InviteUser-Response" },
	{ 0x1B, "KeepAlive-Request" },
	{ 0x1C, "KeepAliveTime" },
	{ 0x1D, "Login-Request" },
	{ 0x1E, "Login-Response" },
	{ 0x1F, "Logout-Request" },
	{ 0x20, "Nonce" },
	{ 0x21, "Password" },
	{ 0x22, "Polling-Request" },
	{ 0x23, "ResponseNote" },
	{ 0x24, "SearchElement" },
	{ 0x25, "SearchFindings" },
	{ 0x26, "SearchID" },
	{ 0x27, "SearchIndex" },
	{ 0x28, "SearchLimit" },
	{ 0x29, "KeepAlive-Response" },
	{ 0x2A, "SearchPairList" },
	{ 0x2B, "Search-Request" },
	{ 0x2C, "Search-Response" },
	{ 0x2D, "SearchResult" },
	{ 0x2E, "Service-Request" },
	{ 0x2F, "Service-Response" },
	{ 0x30, "SessionCookie" },
	{ 0x31, "StopSearch-Request" },
	{ 0x32, "TimeToLive" },
	/* New in WV-CSP 1.1 */
	{ 0x33, "SearchString" },
	{ 0x34, "CompletionFlag" },
	/* New in WV-CSP 1.2 */
	{ 0x36, "ReceiveList" },
	{ 0x37, "VerifyID-Request" },
	{ 0x38, "Extended-Request" },
	{ 0x39, "Extended-Response" },
	{ 0x3A, "AgreedCapabilityList" },
	{ 0x3B, "ExtendedData" },
	{ 0x3C, "OtherServer" },
	{ 0x3D, "PresenceAttributeNSName" },
	{ 0x3E, "SessionNSName" },
	{ 0x3F, "TransactionNSName" },

	{ 0x00, NULL }
};
/* Note that the table continues in code page 0x0A */

/* Service code page (0x02) */
static const value_string wbxml_wv_csp_12_tags_cp2[] = {
	/* 0x00 -- 0x04 GLOBAL */
	{ 0x05, "ADDGM" },
	{ 0x06, "AttListFunc" },
	{ 0x07, "BLENT" },
	{ 0x08, "CAAUT" },
	{ 0x09, "CAINV" },
	{ 0x0A, "CALI" },
	{ 0x0B, "CCLI" },
	{ 0x0C, "ContListFunc" },
	{ 0x0D, "CREAG" },
	{ 0x0E, "DALI" },
	{ 0x0F, "DCLI" },
	{ 0x10, "DELGR" },
	{ 0x11, "FundamentalFeat" },
	{ 0x12, "FWMSG" },
	{ 0x13, "GALS" },
	{ 0x14, "GCLI" },
	{ 0x15, "GETGM" },
	{ 0x16, "GETGP" },
	{ 0x17, "GETLM" },
	{ 0x18, "GETM" },
	{ 0x19, "GETPR" },
	{ 0x1A, "GETSPI" },
	{ 0x1B, "GETWL" },
	{ 0x1C, "GLBLU" },
	{ 0x1D, "GRCHN" },
	{ 0x1E, "GroupAuthFunc" },
	{ 0x1F, "GroupFeat" },
	{ 0x20, "GroupMgmtFunc" },
	{ 0x21, "GroupUseFunc" },
	{ 0x22, "IMAuthFunc" },
	{ 0x23, "IMFeat" },
	{ 0x24, "IMReceiveFunc" },
	{ 0x25, "IMSendFunc" },
	{ 0x26, "INVIT" },
	{ 0x27, "InviteFunc" },
	{ 0x28, "MBRAC" },
	{ 0x29, "MCLS" },
	{ 0x2A, "MDELIV" },
	{ 0x2B, "NEWM" },
	{ 0x2C, "NOTIF" },
	{ 0x2D, "PresenceAuthFunc" },
	{ 0x2E, "PresenceDeliverFunc" },
	{ 0x2F, "PresenceFeat" },
	{ 0x30, "REACT" },
	{ 0x31, "REJCM" },
	{ 0x32, "REJEC" },
	{ 0x33, "RMVGM" },
	{ 0x34, "SearchFunc" },
	{ 0x35, "ServiceFunc" },
	{ 0x36, "SETD" },
	{ 0x37, "SETGP" },
	{ 0x38, "SRCH" },
	{ 0x39, "STSRC" },
	{ 0x3A, "SUBGCN" },
	{ 0x3B, "UPDPR" },
	{ 0x3C, "WVCSPFeat" },
	/* New in WV-CSP 1.2 */
	{ 0x3D, "MF" },
	{ 0x3E, "MG" },
	{ 0x3E, "VRID" }, /* Duplicate, and cp2 is full --> Will move to cp8? */
	{ 0x3F, "MM" },

	{ 0x00, NULL }
};
/* Note that the table continues in code page 0x08 */

/* Client capability code page (0x03) */
/* Same as cp3 of WV-CSP 1.1 */
#define wbxml_wv_csp_12_tags_cp3 wbxml_wv_csp_11_tags_cp3

/* Presence primitive code page (0x04) */
static const value_string wbxml_wv_csp_12_tags_cp4[] = {
	/* 0x00 -- 0x04 GLOBAL */
	{ 0x05, "CancelAuth-Request" },
	{ 0x06, "ContactListProperties" },
	{ 0x07, "CreateAttributeList-Request" },
	{ 0x08, "CreateList-Request" },
	{ 0x09, "DefaultAttributeList" },
	{ 0x0A, "DefaultContactList" },
	{ 0x0B, "DefaultList" },
	{ 0x0C, "DeleteAttributeList-Request" },
	{ 0x0D, "DeleteList-Request" },
	{ 0x0E, "GetAttributeList-Request" },
	{ 0x0F, "GetAttributeList-Response" },
	{ 0x10, "GetList-Request" },
	{ 0x11, "GetList-Response" },
	{ 0x12, "GetPresence-Request" },
	{ 0x13, "GetPresence-Response" },
	{ 0x14, "GetWatcherList-Request" },
	{ 0x15, "GetWatcherList-Response" },
	{ 0x16, "ListManage-Request" },
	{ 0x17, "ListManage-Response" },
	{ 0x18, "UnsubscribePresence-Request" },
	{ 0x19, "PresenceAuth-Request" },
	{ 0x1A, "PresenceAuth-User" },
	{ 0x1B, "PresenceNotification-Request" },
	{ 0x1C, "UpdatePresence-Request" },
	{ 0x1D, "SubscribePresence-Request" },
	/* New in WV-CSP 1.2 */
	{ 0x1E, "Auto-Subscribe" },
	/* 0x1E was defined in WV-CSP 1.0: UnsubscribePresence-Request */
	{ 0x1F, "GetReactiveAuthStatus-Request" },
	/* 0x1F was defined in WV-CSP 1.0: UpdatePresence-Request */
	{ 0x20, "GetReactiveAuthStatus-Response" },

	{ 0x00, NULL }
};

/* Presence attribute code page (0x05) */
static const value_string wbxml_wv_csp_12_tags_cp5[] = {
	/* 0x00 -- 0x04 GLOBAL */
	{ 0x05, "Accuracy" },
	{ 0x06, "Address" },
	{ 0x07, "AddrPref" },
	{ 0x08, "Alias" },
	{ 0x09, "Altitude" },
	{ 0x0A, "Building" },
	{ 0x0B, "Caddr" },
	{ 0x0C, "City" },
	{ 0x0D, "ClientInfo" },
	{ 0x0E, "ClientProducer" },
	{ 0x0F, "ClientType" },
	{ 0x10, "ClientVersion" },
	{ 0x11, "CommC" },
	{ 0x12, "CommCap" },
	{ 0x13, "ContactInfo" },
	{ 0x14, "ContainedvCard" },
	{ 0x15, "Country" },
	{ 0x16, "Crossing1" },
	{ 0x17, "Crossing2" },
	{ 0x18, "DevManufacturer" },
	{ 0x19, "DirectContent" },
	{ 0x1A, "FreeTextLocation" },
	{ 0x1B, "GeoLocation" },
	{ 0x1C, "Language" },
	{ 0x1D, "Latitude" },
	{ 0x1E, "Longitude" },
	{ 0x1F, "Model" },
	{ 0x20, "NamedArea" },
	{ 0x21, "OnlineStatus" },
	{ 0x22, "PLMN" },
	{ 0x23, "PrefC" },
	{ 0x24, "PreferredContacts" },
	{ 0x25, "PreferredLanguage" },
	{ 0x26, "ReferredContent" },
	{ 0x27, "ReferredvCard" },
	{ 0x28, "Registration" },
	{ 0x29, "StatusContent" },
	{ 0x2A, "StatusMood" },
	{ 0x2B, "StatusText" },
	{ 0x2C, "Street" },
	{ 0x2D, "TimeZone" },
	{ 0x2E, "UserAvailability" },
	/* New in WV-CSP 1.1 */
	{ 0x2F, "Cap" },
	{ 0x30, "Cname" },
	{ 0x31, "Contact" },
	{ 0x32, "Cpriority" },
	{ 0x33, "Cstatus" },
	{ 0x34, "Note" },
	{ 0x35, "Zone" },
	/* New in WV-CSP 1.2 */
	{ 0x36, "ContentType" },
	{ 0x37, "Inf_link" },
	{ 0x38, "InfoLink" },
	{ 0x39, "Link" },
	{ 0x3A, "Text" },

	{ 0x00, NULL }
};

/* Messaging code page (0x06) */
static const value_string wbxml_wv_csp_12_tags_cp6[] = {
	/* 0x00 -- 0x04 GLOBAL */
	{ 0x05, "BlockList" },
	{ 0x06, "BlockEntity-Request" }, /* Was: BlockUser-Request */
	{ 0x07, "DeliveryMethod" },
	{ 0x08, "DeliveryReport" },
	{ 0x09, "DeliveryReport-Request" },
	{ 0x0A, "ForwardMessage-Request" },
	{ 0x0B, "GetBlockedList-Request" },
	{ 0x0C, "GetBlockedList-Response" },
	{ 0x0D, "GetMessageList-Request" },
	{ 0x0E, "GetMessageList-Response" },
	{ 0x0F, "GetMessage-Request" },
	{ 0x10, "GetMessage-Response" },
	{ 0x11, "GrantList" },
	{ 0x12, "MessageDelivered" },
	{ 0x13, "MessageInfo" },
	{ 0x14, "MessageNotification" },
	{ 0x15, "NewMessage" },
	{ 0x16, "RejectMessage-Request" },
	{ 0x17, "SendMessage-Request" },
	{ 0x18, "SendMessage-Response" },
	{ 0x19, "SetDeliveryMethod-Request" },
	{ 0x1A, "DeliveryTime" },

	{ 0x00, NULL }
};

/* Group code page (0x07) */
static const value_string wbxml_wv_csp_12_tags_cp7[] = {
	/* 0x00 -- 0x04 GLOBAL */
	{ 0x05, "AddGroupMembers-Request" },
	{ 0x06, "Admin" },
	{ 0x07, "CreateGroup-Request" },
	{ 0x08, "DeleteGroup-Request" },
	{ 0x09, "GetGroupMembers-Request" },
	{ 0x0A, "GetGroupMembers-Response" },
	{ 0x0B, "GetGroupProps-Request" },
	{ 0x0C, "GetGroupProps-Response" },
	{ 0x0D, "GroupChangeNotice" },
	{ 0x0E, "GroupProperties" },
	{ 0x0F, "Joined" },
	{ 0x10, "JoinedRequest" },
	{ 0x11, "JoinGroup-Request" },
	{ 0x12, "JoinGroup-Response" },
	{ 0x13, "LeaveGroup-Request" },
	{ 0x14, "LeaveGroup-Response" },
	{ 0x15, "Left" },
	{ 0x16, "MemberAccess-Request" },
	{ 0x17, "Mod" },
	{ 0x18, "OwnProperties" },
	{ 0x19, "RejectList-Request" },
	{ 0x1A, "RejectList-Response" },
	{ 0x1B, "RemoveGroupMembers-Request" },
	{ 0x1C, "SetGroupProps-Request" },
	{ 0x1D, "SubscribeGroupNotice-Request" },
	{ 0x1E, "SubscribeGroupNotice-Response" },
	{ 0x1F, "Users" },
	{ 0x20, "WelcomeNote" },
	/* New in WV-CSP 1.1 */
	{ 0x21, "JoinGroup" },
	{ 0x22, "SubscribeNotification" },
	{ 0x23, "SubscribeType" },
	/* New in WV-CSP 1.2 */
	{ 0x24, "GetJoinedUsers-Request" },
	{ 0x25, "GetJoinedUsers-Response" },
	{ 0x26, "AdminMapList" },
	{ 0x27, "AdminMapping" },
	{ 0x28, "Mapping" },
	{ 0x29, "ModMapping" },
	{ 0x2A, "UserMapList" },
	{ 0x2B, "UserMapping" },

	{ 0x00, NULL }
};

/* Service negotiation code page - continued (0x08) */
/* Same as cp8 of WV-CSP 1.1, but a new token is likely to be added. - XXX */
static const value_string wbxml_wv_csp_12_tags_cp8[] = {
	/* 0x00 -- 0x04 GLOBAL */
	{ 0x05, "MP" },
	{ 0x06, "GETAUT" },
	{ 0x07, "GETJU" },

	{ 0x00, NULL }
};

/* Common code page - continued (0x09) */
static const value_string wbxml_wv_csp_12_tags_cp9[] = {
	/* 0x00 -- 0x04 GLOBAL */
	{ 0x05, "CIR" },
	{ 0x06, "Domain" },
	{ 0x07, "ExtBlock" },
	{ 0x08, "HistoryPeriod" },
	{ 0x09, "IDList" },
	{ 0x0A, "MaxWatcherList" },
	{ 0x0B, "ReactiveAuthState" },
	{ 0x0C, "ReactiveAuthStatus" },
	{ 0x0D, "ReactiveAuthStatusList" },
	{ 0x0E, "Watcher" },
	{ 0x0C, "WatcherStatus" }, /* Duplicate --> Will move to 0x0F? */

	{ 0x00, NULL }
};

/* Access code page - continued (0x0A) */
static const value_string wbxml_wv_csp_12_tags_cp10[] = {
	/* 0x00 -- 0x04 GLOBAL */
	{ 0x05, "WV-CSP-NSDiscovery-Request" },
	{ 0x06, "WV-CSP-NSDiscovery-Response" },

	{ 0x00, NULL }
};

/*****    Attribute Start tokens   *****/
/* Common code page (0x00) */
static const value_string wbxml_wv_csp_12_attrStart_cp0[] = {
	/* 0x00 -- 0x04 GLOBAL */
	{ 0x05, "xmlns='http://www.wireless-village.org/CSP'" },
	{ 0x06, "xmlns='http://www.wireless-village.org/PA'" },
	{ 0x07, "xmlns='http://www.wireless-village.org/TRC'" },
	/* New in WV-CSP 1.2 */
	{ 0x08, "xmlns='http://www.openmobilealliance.org/DTD/WV-CSP'" },
	{ 0x09, "xmlns='http://www.openmobilealliance.org/DTD/WV-PA'" },
	{ 0x0A, "xmlns http://www.openmobilealliance.org/DTD/WV-TRC'" },

	{ 0x00, NULL }
};

/*****    Attribute Value tokens   *****/
/*
 * Element value tokens
 *
 * NOTE - WV-CSP uses the EXT_T_0 token in a peculiar way: the mb_u_int32
 * does *not* reference an offset in the string table, but it refers to
 * the index in the following value_string.
 *
 * Please note that:
 *  - Values 'T' and 'F' are Boolean values representing "True" and "False"
 *    (or "Yes" and "No" in some circumstances) respectively.
 *  - Values 'GR', 'IM', 'PR', 'SC', 'GM' and 'US' are enumerated values
 *    representing "Group", "Instant Messaging", "Presence", "Shared Content",
 *    "Group membership" and "User" respectively.
 *  - Values 'G', 'S' and 'U' are enumerated values representing "Get", "Set"
 *    and "Unset" respectively.
 *  - Values 'N' and 'P' are enumerated values representing "Notify/Get" and
 *    "Push" respectively.
 *
 * I repeat: this is NOT a attrValue[] array hence it is not called
 * wbxml_wv_XXX but vals_wv_XXX.
 */
static const value_string vals_wv_csp_12_element_value_tokens[] = {
	/*
	 * Common value tokens
	 */
	{ 0x00, "AccessType" },
	{ 0x01, "ActiveUsers" },
	{ 0x02, "Admin" },
	{ 0x03, "application/" },
	{ 0x04, "application/vnd.wap.mms-message" },
	{ 0x05, "application/x-sms" },
	{ 0x06, "AutoJoin" },
	{ 0x07, "BASE64" },
	{ 0x08, "Closed" },
	{ 0x09, "Default" },
	{ 0x0A, "DisplayName" },
	{ 0x0B, "F" },
	{ 0x0C, "G" },
	{ 0x0D, "GR" },
	{ 0x0E, "http://" },
	{ 0x0F, "https://" },
	{ 0x10, "image/" },
	{ 0x11, "Inband" },
	{ 0x12, "IM" },
	{ 0x13, "MaxActiveUsers" },
	{ 0x14, "Mod" },
	{ 0x15, "Name" },
	{ 0x16, "None" },
	{ 0x17, "N" },
	{ 0x18, "Open" },
	{ 0x19, "Outband" },
	{ 0x1A, "PR" },
	{ 0x1B, "Private" },
	{ 0x1C, "PrivateMessaging" },
	{ 0x1D, "PrivilegeLevel" },
	{ 0x1E, "Public" },
	{ 0x1F, "P" },
	{ 0x20, "Request" },
	{ 0x21, "Response" },
	{ 0x22, "Restricted" },
	{ 0x23, "ScreenName" },
	{ 0x24, "Searchable" },
	{ 0x25, "S" },
	{ 0x26, "SC" },
	{ 0x27, "text/" },
	{ 0x28, "text/plain" },
	{ 0x29, "text/x-vCalendar" },
	{ 0x2A, "text/x-vCard" },
	{ 0x2B, "Topic" },
	{ 0x2C, "T" },
	{ 0x2D, "Type" },
	{ 0x2E, "U" },
	{ 0x2F, "US" },
	{ 0x30, "www.wireless-village.org" },
	/* New in WV-CSP 1.2 */
	{ 0x31, "AutoDelete" },
	{ 0x32, "GM" },
	{ 0x33, "Validity" },
	{ 0x34, "DENIED" }, /* Duplicate */
	{ 0x34, "ShowID" }, /* Duplicate */
	{ 0x35, "GRANTED" },
	{ 0x36, "PENDING" },
	/*
	 * Access value tokens
	 */
	{ 0x3D, "GROUP_ID" },
	{ 0x3E, "GROUP_NAME" },
	{ 0x3F, "GROUP_TOPIC" },
	{ 0x40, "GROUP_USER_ID_JOINED" },
	{ 0x41, "GROUP_USER_ID_OWNER" },
	{ 0x42, "HTTP" },
	{ 0x43, "SMS" },
	{ 0x44, "STCP" },
	{ 0x45, "SUDP" },
	{ 0x46, "USER_ALIAS" },
	{ 0x47, "USER_EMAIL_ADDRESS" },
	{ 0x48, "USER_FIRST_NAME" },
	{ 0x49, "USER_ID" },
	{ 0x4A, "USER_LAST_NAME" },
	{ 0x4B, "USER_MOBILE_NUMBER" },
	{ 0x4C, "USER_ONLINE_STATUS" },
	{ 0x4D, "WAPSMS" },
	{ 0x4E, "WAPUDP" },
	{ 0x4F, "WSP" },
	/* New in WV-CSP 1.2 */
	{ 0x50, "GROUP_USER_ID_AUTOJOIN" },
	/*
	 * Presence value tokens
	 */
	{ 0x5B, "ANGRY" },
	{ 0x5C, "ANXIOUS" },
	{ 0x5D, "ASHAMED" },
	{ 0x5E, "AUDIO_CALL" },
	{ 0x5F, "AVAILABLE" },
	{ 0x60, "BORED" },
	{ 0x61, "CALL" },
	{ 0x62, "CLI" },
	{ 0x63, "COMPUTER" },
	{ 0x64, "DISCREET" },
	{ 0x65, "EMAIL" },
	{ 0x66, "EXCITED" },
	{ 0x67, "HAPPY" },
	{ 0x68, "IM" },
	{ 0x69, "IM_OFFLINE" },
	{ 0x6A, "IM_ONLINE" },
	{ 0x6B, "IN_LOVE" },
	{ 0x6C, "INVINCIBLE" },
	{ 0x6D, "JEALOUS" },
	{ 0x6E, "MMS" },
	{ 0x6F, "MOBILE_PHONE" },
	{ 0x70, "NOT_AVAILABLE" },
	{ 0x71, "OTHER" },
	{ 0x72, "PDA" },
	{ 0x73, "SAD" },
	{ 0x74, "SLEEPY" },
	{ 0x75, "SMS" },
	{ 0x76, "VIDEO_CALL" },
	{ 0x77, "VIDEO_STREAM" },

	{ 0x00, NULL }
};



/***** Token code page aggregation *****/

static char *
ext_t_0_wv_cspc_12(tvbuff_t *tvb _U_, guint32 value, guint32 str_tbl _U_)
{
    char *str = g_strdup_printf("Common Value: '%s'",
	    val_to_str(value, vals_wv_csp_12_element_value_tokens,
		"<Unknown WV-CSP 1.2 Common Value token 0x%X>"));
    return str;
}

#define wbxml_wv_csp_12_global wbxml_wv_csp_11_global

static const value_valuestring wbxml_wv_csp_12_tags[] = {
	{  0, wbxml_wv_csp_12_tags_cp0 },
	{  1, wbxml_wv_csp_12_tags_cp1 },
	{  2, wbxml_wv_csp_12_tags_cp2 },
	{  3, wbxml_wv_csp_12_tags_cp3 },
	{  4, wbxml_wv_csp_12_tags_cp4 },
	{  5, wbxml_wv_csp_12_tags_cp5 },
	{  6, wbxml_wv_csp_12_tags_cp6 },
	{  7, wbxml_wv_csp_12_tags_cp7 },
	{  8, wbxml_wv_csp_12_tags_cp8 },
	{  9, wbxml_wv_csp_12_tags_cp9 },
	{ 10, wbxml_wv_csp_12_tags_cp10 },
	{  0, NULL }
};

static const value_valuestring wbxml_wv_csp_12_attrStart[] = {
	{ 0, wbxml_wv_csp_12_attrStart_cp0 },
	{ 0, NULL }
};

static const wbxml_decoding decode_wv_cspc_12 = {
    "Wireless-Village Client-Server Protocol 1.2",
    "WV-CSP 1.2",
    { ext_t_0_wv_cspc_12, NULL, NULL },
	wv_csp12_opaque_binary_tag,
	default_opaque_literal_tag,
	default_opaque_binary_attr,
	default_opaque_literal_attr,
    wbxml_wv_csp_12_global,
    wbxml_wv_csp_12_tags,
    wbxml_wv_csp_12_attrStart,
    NULL
};
#endif /* Remove_this_comment_when_WV_CSP_will_be_an_approved_spec */





/****************************** Discriminators ******************************/
/* Discriminator for WV-CSP; allows version detection based on parsing parts
 * of the start of the WBXML body.
 */
static const wbxml_decoding *
wv_csp_discriminator(tvbuff_t *tvb, guint32 offset)
{
	guint32 magic_1 = tvb_get_ntohl(tvb, offset + 0);
	guint16 magic_2 = tvb_get_ntohs(tvb, offset + 4);

	if (magic_1 == 0xFE050331 && magic_2 == 0x2e30) {
		/* FE 05 03 31 23 30 --> WV-CSP 1.0 */
		return &decode_wv_cspc_10;
	} else if (magic_1 == 0xC9050331 && magic_2 == 0x2e31) {
		/* C9 05 03 31 23 31 --> WV-CSP 1.1 */
		return &decode_wv_cspc_11;
#ifdef Remove_this_comment_when_WV_CSP_will_be_an_approved_spec
	} else if (magic_1 == 0xC9050331 && magic_2 == 0x2e31) {
		/* C9 05 03 31 23 32 --> WV-CSP 1.2 */
		return &decode_wv_cspc_12;
#endif /* Remove_this_comment_when_WV_CSP_will_be_an_approved_spec */
	}

	/* Default: WV-CSP 1.1 */
	return &decode_wv_cspc_11;
}

/********************** WBXML token mapping aggregation **********************/

static const wbxml_decoding *get_wbxml_decoding_from_public_id (guint32 publicid);
static const wbxml_decoding *get_wbxml_decoding_from_content_type (
	const char *content_type, tvbuff_t *tvb, guint32 offset);


/**
 ** Aggregation of content type and aggregated code pages
 ** Content type map lookup will stop at the 1st entry with 3rd member = FALSE
 **/

/*
 * The following map contains entries registered with a registered WBXML
 * public ID. See WAP WINA or OMA OMNA for registered values:
 * http://www.openmobilealliance.org/tech/omna/ */
static const wbxml_integer_list well_known_public_id_list[] = {
    /* 0x00 - Unknown or missing Public ID */
    /* 0x01 - LITERAL PublicID - see String Table */
    { 0x02,	&decode_wmlc_10 },	/* WML 1.0 */
    /* 0x03 - WTA 1.0 */
    { 0x04,	&decode_wmlc_11 },	/* WML 1.1 */
    { 0x05,	&decode_sic_10 },	/* SI 1.0 */
    { 0x06,	&decode_slc_10 },	/* SL 1.0 */
    { 0x07,	&decode_coc_10 },	/* CO 1.0 */
    { 0x08,	&decode_channelc_10 },	/* CHANNEL 1.0 */
    { 0x09,	&decode_wmlc_12 },	/* WML 1.2 */
    { 0x0A,	&decode_wmlc_13 },	/* WML 1.3 */
    { 0x0B,	&decode_provc_10 },	/* PROV 1.0 */
    /* 0x0C - WTA-WML 1.2 */
    { 0x0D,	&decode_emnc_10 },	/* EMN 1.0 */
    /* 0x0E - DRMREL 1.0 */
    { 0x0F,	&decode_wv_cspc_10 },	/* WV-CSP 1.0 */
    { 0x10,	&decode_wv_cspc_11 },	/* WV-CSP 1.1 */

    { 0x020B,	&decode_nokiaprovc_70 },/* Nokia OTA Provisioning 7.0 */
    { 0x0FD1,	&decode_syncmlc_10 },	/* SyncML 1.0 */
    { 0x0FD3,	&decode_syncmlc_11 },	/* SyncML 1.1 */
    /* Note: I assumed WML+ 1.x would be not that different from WML 1.x,
     *       the real mapping should come from Phone.com (OpenWave)! */
    { 0x1108,	&decode_wmlc_11 },	/* Phone.com WMLC+ 1.1 - not 100% correct */
    { 0x110D,	&decode_wmlc_13 },	/* Phone.com WMLC+ 1.3 - not 100% correct */

    { 0x00,	NULL }
};

/* The following map contains entries only registered with a literal media
 * type. */
static const wbxml_literal_list content_type_list[] = {
    {	"application/x-wap-prov.browser-settings",
	NULL,
	&decode_nokiaprovc_70
    },
    {	"application/x-wap-prov.browser-bookmarks",
	NULL,
	&decode_nokiaprovc_70
    },
    {	"application/vnd.wv.csp.wbxml",
	wv_csp_discriminator,
	&decode_wv_cspc_11
    },
    {	NULL, NULL, NULL }
};
	

/* Returns a pointer to the WBXML token map for the given WBXML public
 * identifier value (see WINA for a table with defined identifiers). */
static const wbxml_decoding *get_wbxml_decoding_from_public_id (guint32 public_id)
{
    const wbxml_decoding *map = NULL;

    DebugLog(("get_wbxml_decoding_from_public_id: public_id = %u\n",
		public_id));
    if (public_id >= 2) {
	const wbxml_integer_list *item = well_known_public_id_list;

	while (item && item->public_id && item->map) {
	    if (item->public_id == public_id) {
		map = item->map;
		break;
	    }
	    item++;
	}
    }
    return map;
}

static const wbxml_decoding *get_wbxml_decoding_from_content_type (
	const char *content_type, tvbuff_t *tvb, guint32 offset)
{
    const wbxml_decoding *map = NULL;

    DebugLog(("get_wbxml_decoding_from_content_type: content_type = [%s]\n",
		content_type));
    if (content_type && content_type[0]) {
    	const wbxml_literal_list *item = content_type_list;

	while (item && item->content_type) {
	    if (strcasecmp(content_type, item->content_type) == 0) {
		/* Try the discriminator */
		if (item->discriminator != NULL) {
		    map = item->discriminator(tvb, offset);
		}
		if (map == NULL) {
    		    map = item->map;
		}
		break;
	    }
	    item++;
	}
    }
    return map;
}


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





/************************** Function prototypes **************************/


static void
dissect_wbxml(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static void
dissect_uaprof(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static void
dissect_wbxml_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
		const wbxml_decoding *override_content_map);

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
		const wbxml_decoding *map);

/* Parse data while in ATTR state */
static guint32
parse_wbxml_attribute_list (proto_tree *tree, tvbuff_t *tvb,
		guint32 offset, guint32 str_tbl, guint8 level, guint8 *codepage_attr);

/* Parse data while in ATTR state;
 * interpret tokens as defined by content type */
static guint32
parse_wbxml_attribute_list_defined (proto_tree *tree, tvbuff_t *tvb,
		guint32 offset, guint32 str_tbl, guint8 level, guint8 *codepage_attr,
		const wbxml_decoding *map);


/****************** WBXML protocol dissection functions ******************/


static void
dissect_wbxml(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_wbxml_common(tvb, pinfo, tree, NULL);
}

static void
dissect_uaprof(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_wbxml_common(tvb, pinfo, tree, &decode_uaprof_wap_248);
}

/* Code to actually dissect the packets */
static void
dissect_wbxml_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
		const wbxml_decoding *override_content_map)
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
	const wbxml_decoding *content_map = NULL;
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
			DISSECTOR_ASSERT_NOT_REACHED();
			break;
	}

	/* String table: read string table length in bytes */
	str_tbl_len = tvb_get_guintvar (tvb, offset, &str_tbl_len_len);
	str_tbl = offset + str_tbl_len_len; /* Start of 1st string in string table */

	/* Compose the summary line */
	if ( publicid ) {
		summary = g_strdup_printf("%s, Public ID: \"%s\"",
				val_to_str (version, vals_wbxml_versions, "(unknown 0x%x)"),
				val_to_str (publicid, vals_wbxml_public_ids, "(unknown 0x%x)"));
	} else {
		/* Read length of Public ID from string table */
		len = tvb_strsize (tvb, str_tbl + publicid_index);
		summary = g_strdup_printf("%s, Public ID: \"%s\"",
				val_to_str (version, vals_wbxml_versions, "(unknown 0x%x)"),
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
		if (disable_wbxml_token_parsing) {
		    ti = proto_tree_add_text (wbxml_tree, tvb, offset, -1,
			    "Data representation not shown "
			    "(edit WBXML preferences to show)");
		    return;
		} /* Else: render the WBXML tokens */
		ti = proto_tree_add_text (wbxml_tree, tvb, offset, -1,
				"Data representation");
		wbxml_content_tree = proto_item_add_subtree (ti, ett_wbxml_content);

		/* The parse_wbxml_X() functions will process the content correctly,
		 * irrespective of the WBXML version used. For the WBXML body, this
		 * means that there is a different processing for the global token
		 * RESERVED_2 (WBXML 1.0) or OPAQUE (WBXML 1.x with x > 0).  */
		if (wbxml_tree) { /* Show only if visible */
			if (override_content_map != NULL) {
				content_map = override_content_map;
				proto_item_append_text(ti,
						" is based on: %s",
						content_map->name);
			} else {
				/* Retrieve the content token mapping if available */
				content_map = get_wbxml_decoding_from_public_id (publicid);
				if (! content_map) {
					content_map = get_wbxml_decoding_from_content_type(
							pinfo->match_string, tvb, offset);
					if (! content_map) {
						proto_tree_add_text (wbxml_content_tree,
								tvb, offset, -1,
								"[Rendering of this content type"
								" not (yet) supported]");
					} else {
						proto_item_append_text(ti,
								" is based on Content-Type: %s "
								"(chosen decoding: %s)",
								pinfo->match_string, content_map->name);
					}
				}
			}
		    if (content_map && skip_wbxml_token_mapping) {
			proto_tree_add_text (wbxml_content_tree,
				tvb, offset, -1,
				"[Rendering of this content type"
				" has been disabled "
				"(edit WBXML preferences to enable)]");
			content_map = NULL;
		    }
		    proto_tree_add_text (wbxml_content_tree, tvb,
			    offset, -1,
			    "Level | State | Codepage "
			    "| WBXML Token Description         "
			    "| Rendering");
		    if (content_map) {
			len = parse_wbxml_tag_defined (wbxml_content_tree,
				tvb, offset, str_tbl, &level, &codepage_stag,
				&codepage_attr, content_map);
		    } else {
			/* Default: WBXML only, no interpretation of the content */
			len = parse_wbxml_tag (wbxml_content_tree, tvb, offset,
				str_tbl, &level, &codepage_stag, &codepage_attr);
		    }
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
 * The wbxml_decoding entry *map contains the actual token mapping.
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
		const wbxml_decoding *map)
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
							tag_save_literal ? tag_save_literal : "");
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
						map_token (map->global, 0, peek),
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
				{   char *s;
				    if (map->ext_t[peek & 0x03])
					s = (map->ext_t[peek & 0x03])(tvb, index, str_tbl);
				    else
					s = g_strdup_printf("EXT_T_%1x (%s)", peek & 0x03, 
						map_token (map->global, 0, peek));
    				    proto_tree_add_text (tree, tvb, off, 1+len,
						"  %3d | Tag   | T %3d    "
						"| EXT_T_%1x    (Extension Token)    "
						"| %s%s",
						*level, *codepage_stag, peek & 0x0f, Indent (*level),
						s);
				    g_free(s);
				}
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
						map_token (map->global, 0, peek));
				off++;
				break;
			case 0xC3: /* OPAQUE - WBXML 1.1 and newer */
				if (tvb_get_guint8 (tvb, 0)) { /* WBXML 1.x (x > 0) */
					char *str;
					if (tag_save_known) { /* Knwon tag */
						if (map->opaque_binary_tag) {
							str = map->opaque_binary_tag(tvb, off + 1,
									tag_save_known, *codepage_stag, &len);
						} else {
							str = default_opaque_binary_tag(tvb, off + 1,
									tag_save_known, *codepage_stag, &len);
						}
					} else { /* lITERAL tag */
						if (map->opaque_literal_tag) {
							str = map->opaque_literal_tag(tvb, off + 1,
									tag_save_literal, *codepage_stag, &len);
						} else {
							str = default_opaque_literal_tag(tvb, off + 1,
									tag_save_literal, *codepage_stag, &len);
						}
					}
					proto_tree_add_text (tree, tvb, off, 1 + len,
							"  %3d | Tag   | T %3d    "
							"| OPAQUE (Opaque data)            "
							"| %s%s",
							*level, *codepage_stag, Indent (*level), str);
					g_free(str);
					off += 1 + len;
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
	char *tag_save_buf=NULL; /* Will contain "tag_0x%02X" */
	char *tag_new_buf=NULL; /* Will contain "tag_0x%02X" */
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
							tag_save_literal ? tag_save_literal : "");
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
				proto_tree_add_text (tree, tvb, off, 1+len,
						"  %3d | Tag   | T %3d    "
						"| EXT_T_%1x    (Extension Token)    "
						"| %s(Extension Token, integer value: %u)",
						*level, *codepage_stag, peek & 0x0f, Indent (*level),
						index);
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
				tag_new_buf=ep_alloc(10);
				g_snprintf (tag_new_buf, 10, "Tag_0x%02X",
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
						tag_save_buf=ep_alloc(10);
						g_snprintf (tag_save_buf, 10, "Tag_0x%02X",
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
 * The wbxml_decoding entry *map contains the actual token mapping.
 *
 * NOTE: See above for known token mappings.
 */
static guint32
parse_wbxml_attribute_list_defined (proto_tree *tree, tvbuff_t *tvb,
		guint32 offset, guint32 str_tbl, guint8 level, guint8 *codepage_attr,
		const wbxml_decoding *map)
{
	guint32 tvb_len = tvb_reported_length (tvb);
	guint32 off = offset;
	guint32 len;
	guint str_len;
	guint32 ent;
	guint32 index;
	guint8 peek;
	guint8 attr_save_known = 0; /* Will contain peek & 0x3F (attr identity) */
	const char *attr_save_literal = NULL; /* Will contain the LITERAL attr identity */

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
				/* ALWAYS means the start of a new attribute,
				 * and may only contain the NAME of the attribute.
				 */
				index = tvb_get_guintvar (tvb, off+1, &len);
				str_len = tvb_strsize (tvb, str_tbl+index);
				attr_save_known = 0;
				attr_save_literal = tvb_format_text (tvb,
						str_tbl+index, str_len-1);
				proto_tree_add_text (tree, tvb, off, 1+len,
						"  %3d |  Attr | A %3d    "
						"| LITERAL (Literal Attribute)     "
						"|   %s<%s />",
						level, *codepage_attr, Indent (level),
						attr_save_literal);
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
						map_token (map->global, 0, peek),
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
				{   char *s;

				    if (map->ext_t[peek & 0x03])
					s = (map->ext_t[peek & 0x03])(tvb, index, str_tbl);
				    else
					s = g_strdup_printf("EXT_T_%1x (%s)", peek & 0x03, 
						map_token (map->global, 0, peek));

    				    proto_tree_add_text (tree, tvb, off, 1+len,
						"  %3d | Tag   | T %3d    "
						"| EXT_T_%1x    (Extension Token)    "
						"| %s%s)",
						level, *codepage_attr, peek & 0x0f, Indent (level),
						s);
				    g_free(s);
				}
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
						map_token (map->global, 0, peek));
				off++;
				break;
			case 0xC3: /* OPAQUE - WBXML 1.1 and newer */
				if (tvb_get_guint8 (tvb, 0)) { /* WBXML 1.x (x > 0) */
					char *str;
					if (attr_save_known) { /* Knwon attribute */
						if (map->opaque_binary_attr) {
							str = map->opaque_binary_attr(tvb, off + 1,
									attr_save_known, *codepage_attr, &len);
						} else {
							str = default_opaque_binary_attr(tvb, off + 1,
									attr_save_known, *codepage_attr, &len);
						}
					} else { /* lITERAL attribute */
						if (map->opaque_literal_tag) {
							str = map->opaque_literal_attr(tvb, off + 1,
									attr_save_literal, *codepage_attr, &len);
						} else {
							str = default_opaque_literal_attr(tvb, off + 1,
									attr_save_literal, *codepage_attr, &len);
						}
					}
					proto_tree_add_text (tree, tvb, off, 1 + len,
							"  %3d |  Attr | A %3d    "
							"| OPAQUE (Opaque data)            "
							"|       %s%s",
							level, *codepage_attr, Indent (level), str);
					g_free(str);
					off += 1 + len;
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
						val_to_str (peek, vals_wbxml1x_global_tokens, "(unknown 0x%x)"));
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
				attr_save_known = peek & 0x7f;
				proto_tree_add_text (tree, tvb, off, 1,
						"  %3d |  Attr | A %3d    "
						"|   Known attrStart 0x%02X          "
						"|   %s%s",
						level, *codepage_attr, attr_save_known, Indent (level),
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
				proto_tree_add_text (tree, tvb, off, 1+len,
						"  %3d |  Attr | A %3d    "
						"| EXT_T_%1x    (Extension Token)    "
						"|     %s(Extension Token, integer value: %u)",
						level, *codepage_attr, peek & 0x0f, Indent (level),
						index);
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
						val_to_str (peek, vals_wbxml1x_global_tokens, "(unknown 0x%x)"));
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
{
	module_t *wbxml_module;	/* WBXML Preferences */

	/* Setup list of header fields. */
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

	/* Preferences */
	wbxml_module = prefs_register_protocol(proto_wbxml, NULL);
	prefs_register_bool_preference(wbxml_module,
			"skip_wbxml_token_mapping",
			"Skip the mapping of WBXML tokens to media type tokens.",
			"Enable this preference if you want to view the WBXML "
			"tokens without the representation in a media type "
			"(e.g., WML). Tokens will show up as Tag_0x12, "
			"attrStart_0x08 or attrValue_0x0B for example.",
			&skip_wbxml_token_mapping);
	prefs_register_bool_preference(wbxml_module,
			"disable_wbxml_token_parsing",
			"Disable the parsing of the WBXML tokens.",
			"Enable this preference if you want to skip the "
			"parsing of the WBXML tokens that constitute the body "
			"of the WBXML document. Only the WBXML header will be "
			"dissected (and visualized) then.",
			&disable_wbxml_token_parsing);

	register_dissector("wbxml", dissect_wbxml, proto_wbxml);
	register_dissector("wbxml-uaprof", dissect_uaprof, proto_wbxml);
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
	dissector_add_string("media_type",
			"application/vnd.wv.csp.wbxml", wbxml_handle);

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
