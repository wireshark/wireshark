/* packet-ipp.c
 * Routines for IPP packet disassembly
 *
 * Guy Harris <guy@alum.mit.edu>
 *
 * $Id: packet-ipp.c,v 1.4 2000/01/22 06:22:13 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
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
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#include <string.h>
#include <ctype.h>

#include <glib.h>
#include "packet.h"

static int proto_ipp = -1;

static gint ett_ipp = -1;
static gint ett_ipp_as = -1;
static gint ett_ipp_attr = -1;

#define	PRINT_JOB		0x0002
#define	PRINT_URI		0x0003
#define	VALIDATE_JOB		0x0004
#define	CREATE_JOB		0x0005
#define	SEND_DOCUMENT		0x0006
#define	SEND_URI		0x0007
#define	CANCEL_JOB		0x0008
#define	GET_JOB_ATTRIBUTES	0x0009
#define	GET_JOBS		0x000A
#define	GET_PRINTER_ATTRIBUTES	0x000B

static const value_string operation_vals[] = {
    { PRINT_JOB,              "Print-Job" },
    { PRINT_URI,              "Print-URI" },
    { VALIDATE_JOB,           "Validate-Job" },
    { CREATE_JOB,             "Create-Job" },
    { SEND_DOCUMENT,          "Send-Document" },
    { SEND_URI,               "Send-URI" },
    { CANCEL_JOB,             "Cancel-Job" },
    { GET_JOB_ATTRIBUTES,     "Get-Job-Attributes" },
    { GET_JOBS,               "Get-Jobs" },
    { GET_PRINTER_ATTRIBUTES, "Get-Printer-Attributes" },
    { 0,                      NULL }
};

#define	STATUS_SUCCESSFUL	0x0000
#define	STATUS_INFORMATIONAL	0x0100
#define	STATUS_REDIRECTION	0x0200
#define	STATUS_CLIENT_ERROR	0x0400
#define	STATUS_SERVER_ERROR	0x0500

#define	STATUS_TYPE_MASK	0xFF00

#define	SUCCESSFUL_OK				0x0000
#define	SUCCESSFUL_OK_IGN_OR_SUB_ATTR		0x0001
#define	SUCCESSFUL_OK_CONFLICTING_ATTR		0x0002

#define	CLIENT_ERROR_BAD_REQUEST		0x0400
#define	CLIENT_ERROR_FORBIDDEN			0x0401
#define	CLIENT_ERROR_NOT_AUTHENTICATED		0x0402
#define	CLIENT_ERROR_NOT_AUTHORIZED		0x0403
#define	CLIENT_ERROR_NOT_POSSIBLE		0x0404
#define	CLIENT_ERROR_TIMEOUT			0x0405
#define	CLIENT_ERROR_NOT_FOUND			0x0406
#define	CLIENT_ERROR_GONE			0x0407
#define	CLIENT_ERROR_REQ_ENTITY_TOO_LRG		0x0408
#define	CLIENT_ERROR_REQ_VALUE_TOO_LONG		0x0409
#define	CLIENT_ERROR_DOC_FMT_NOT_SUPP		0x040A
#define	CLIENT_ERROR_ATTR_OR_VAL_NOT_SUPP	0x040B
#define	CLIENT_ERROR_URI_SCHEME_NOT_SUPP	0x040C
#define	CLIENT_ERROR_CHARSET_NOT_SUPP		0x040D
#define	CLIENT_ERROR_CONFLICTING_ATTRS		0x040E

#define	SERVER_ERROR_INTERNAL_ERROR		0x0500
#define	SERVER_ERROR_OPERATION_NOT_SUPP		0x0501
#define	SERVER_ERROR_SERVICE_UNAVAIL		0x0502
#define	SERVER_ERROR_VERSION_NOT_SUPP		0x0503
#define	SERVER_ERROR_DEVICE_ERROR		0x0504
#define	SERVER_ERROR_TEMPORARY_ERROR		0x0505
#define	SERVER_ERROR_NOT_ACCEPTING_JOBS		0x0506
#define	SERVER_ERROR_BUSY			0x0507
#define	SERVER_ERROR_JOB_CANCELED		0x0508

static const value_string status_vals[] = {
    { SUCCESSFUL_OK,                     "Successful-OK" },
    { SUCCESSFUL_OK_IGN_OR_SUB_ATTR,     "Successful-OK-Ignored-Or-Substituted-Attributes" },
    { SUCCESSFUL_OK_CONFLICTING_ATTR,    "Successful-OK-Conflicting-Attributes" },
    { CLIENT_ERROR_BAD_REQUEST,          "Client-Error-Bad-Request" },
    { CLIENT_ERROR_FORBIDDEN,            "Client-Error-Forbidden" },
    { CLIENT_ERROR_NOT_AUTHENTICATED,    "Client-Error-Not-Authenticated" },
    { CLIENT_ERROR_NOT_AUTHORIZED,       "Client-Error-Not-Authorized" },
    { CLIENT_ERROR_NOT_POSSIBLE,         "Client-Error-Not-Possible" },
    { CLIENT_ERROR_TIMEOUT,              "Client-Error-Timeout" },
    { CLIENT_ERROR_NOT_FOUND,            "Client-Error-Not-Found" },
    { CLIENT_ERROR_GONE,                 "Client-Error-Gone" },
    { CLIENT_ERROR_REQ_ENTITY_TOO_LRG,   "Client-Error-Request-Entity-Too-Large" },
    { CLIENT_ERROR_REQ_VALUE_TOO_LONG,   "Client-Error-Request-Value-Too-Long" },
    { CLIENT_ERROR_DOC_FMT_NOT_SUPP,     "Client-Error-Document-Format-Not-Supported" },
    { CLIENT_ERROR_ATTR_OR_VAL_NOT_SUPP, "Client-Error-Attributes-Or-Values-Not-Supported" },
    { CLIENT_ERROR_URI_SCHEME_NOT_SUPP,  "Client-Error-URI-Scheme-Not-Supported" },
    { CLIENT_ERROR_CHARSET_NOT_SUPP,     "Client-Error-Charset-Not-Supported" },
    { CLIENT_ERROR_CONFLICTING_ATTRS,    "Client-Error-Conflicting-Attributes" },
    { SERVER_ERROR_INTERNAL_ERROR,       "Server-Error-Internal-Error" },
    { SERVER_ERROR_OPERATION_NOT_SUPP,   "Server-Error-Operation-Not-Supported" },
    { SERVER_ERROR_SERVICE_UNAVAIL,      "Server-Error-Service-Unavailable" },
    { SERVER_ERROR_VERSION_NOT_SUPP,     "Server-Error-Version-Not-Supported" },
    { SERVER_ERROR_DEVICE_ERROR,         "Server-Error-Device-Error" },
    { SERVER_ERROR_TEMPORARY_ERROR,      "Server-Error-Temporary-Error" },
    { SERVER_ERROR_NOT_ACCEPTING_JOBS,   "Server-Error-Not-Accepting-Jobs" },
    { SERVER_ERROR_BUSY,                 "Server-Error-Busy" },
    { SERVER_ERROR_JOB_CANCELED,         "Server-Error-Job-Canceled" },
    { 0,                                 NULL }
};

static int parse_attributes(const u_char *pd, int offset, frame_data *fd,
    proto_tree *tree);
static proto_tree *add_integer_tree(proto_tree *tree, const u_char *pd,
    int offset, guint name_length, guint value_length);
static void add_integer_value(guint tag, gchar *tag_desc, proto_tree *tree,
    const u_char *pd, int offset, guint name_length, guint value_length);
static proto_tree *add_octetstring_tree(proto_tree *tree, const u_char *pd,
    int offset, guint name_length, guint value_length);
static void add_octetstring_value(guint tag, gchar *tag_desc, proto_tree *tree,
    const u_char *pd, int offset, guint name_length, guint value_length);
static proto_tree *add_charstring_tree(proto_tree *tree, const u_char *pd,
    int offset, guint name_length, guint value_length);
static void add_charstring_value(guint tag, gchar *tag_desc, proto_tree *tree,
    const u_char *pd, int offset, guint name_length, guint value_length);
static int add_value_head(guint tag, gchar *tag_desc, proto_tree *tree,
    const u_char *pd, int offset, guint name_length, guint value_length);

void dissect_ipp(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
	proto_tree *ipp_tree;
	proto_item *ti;
	gboolean is_request = (pi.destport == 631);
	guint16 status_code;
	gchar *status_fmt;

	if (check_col(fd, COL_PROTOCOL))
		col_add_str(fd, COL_PROTOCOL, "IPP");
	if (check_col(fd, COL_INFO)) {
		if (is_request)
			col_add_str(fd, COL_INFO, "IPP request");
		else
			col_add_str(fd, COL_INFO, "IPP response");
	}

	if (tree) {
		ti = proto_tree_add_item(tree, proto_ipp, offset, END_OF_FRAME, NULL);
		ipp_tree = proto_item_add_subtree(ti, ett_ipp);

		proto_tree_add_text(ipp_tree, offset, 2, "Version: %u.%u",
		    pd[offset], pd[offset + 1]);
		offset += 2;

		if (is_request) {
			proto_tree_add_text(ipp_tree, offset, 2, "Operation-id: %s",
			    val_to_str(pntohs(&pd[offset]), operation_vals,
			        "Unknown (0x%04x)"));
		} else {
			status_code = pntohs(&pd[offset]);
			switch (status_code & STATUS_TYPE_MASK) {

			case STATUS_SUCCESSFUL:
				status_fmt = "Successful (0x%04x)";
				break;

			case STATUS_INFORMATIONAL:
				status_fmt = "Informational (0x%04x)";
				break;

			case STATUS_REDIRECTION:
				status_fmt = "Redirection (0x%04x)";
				break;

			case STATUS_CLIENT_ERROR:
				status_fmt = "Client error (0x%04x)";
				break;

			case STATUS_SERVER_ERROR:
				status_fmt = "Server error (0x%04x)";
				break;

			default:
				status_fmt = "Unknown (0x%04x)";
				break;
			}
			proto_tree_add_text(ipp_tree, offset, 2, "Status-code: %s",
			    val_to_str(status_code, status_vals, status_fmt));
		}
		offset += 2;

		proto_tree_add_text(ipp_tree, offset, 4, "Request ID: %u",
		    pntohl(&pd[offset]));
		offset += 4;

		offset = parse_attributes(pd, offset, fd, ipp_tree);

		if (IS_DATA_IN_FRAME(offset))
			dissect_data(pd, offset, fd, ipp_tree);
	}
}

#define	TAG_TYPE(tag)		((tag) & 0xF0)
#define	TAG_TYPE_DELIMITER	0x00
#define	TAG_TYPE_INTEGER	0x20
#define	TAG_TYPE_OCTETSTRING	0x30
#define	TAG_TYPE_CHARSTRING	0x40

#define	TAG_END_OF_ATTRIBUTES	0x03

#define	TAG_INTEGER		0x21
#define	TAG_BOOLEAN		0x22
#define	TAG_ENUM		0x23

#define	TAG_OCTETSTRING		0x30
#define	TAG_DATETIME		0x31
#define	TAG_RESOLUTION		0x32
#define	TAG_RANGEOFINTEGER	0x33
#define	TAG_TEXTWITHLANGUAGE	0x35
#define	TAG_NAMEWITHLANGUAGE	0x36

#define	TAG_TEXTWITHOUTLANGUAGE	0x41
#define	TAG_NAMEWITHOUTLANGUAGE	0x42
#define	TAG_KEYWORD		0x44
#define	TAG_URI			0x45
#define	TAG_URISCHEME		0x46
#define	TAG_CHARSET		0x47
#define	TAG_NATURALLANGUAGE	0x48
#define	TAG_MIMEMEDIATYPE	0x49

static const value_string tag_vals[] = {
	/* Delimiter tags */
	{ 0x01,                    "Operation attributes" },
	{ 0x02,                    "Job attributes" },
	{ TAG_END_OF_ATTRIBUTES,   "End of attributes" },
	{ 0x04,                    "Printer attributes" },
	{ 0x05,                    "Unsupported attributes" },

	/* Value tags */
	{ 0x10,                    "Unsupported" },
	{ 0x12,                    "Unknown" },
	{ 0x13,                    "No value" },
	{ TAG_INTEGER,             "Integer" },
	{ TAG_BOOLEAN,             "Boolean" },
	{ TAG_ENUM,                "Enum" },
	{ TAG_OCTETSTRING,         "Octet string" },
	{ TAG_DATETIME,            "Date/Time" },
	{ TAG_RESOLUTION,          "Resolution" },
	{ TAG_RANGEOFINTEGER,      "Range of integer" },
	{ TAG_TEXTWITHLANGUAGE,    "Text with language" },
	{ TAG_NAMEWITHLANGUAGE,    "Name with language" },
	{ TAG_TEXTWITHOUTLANGUAGE, "Text without language" },
	{ TAG_NAMEWITHOUTLANGUAGE, "Name without language" },
	{ TAG_KEYWORD,             "Keyword" },
	{ TAG_URI,                 "URI" },
	{ TAG_URISCHEME,           "URI scheme" },
	{ TAG_CHARSET,             "Character set" },
	{ TAG_NATURALLANGUAGE,     "Natural language" },
	{ TAG_MIMEMEDIATYPE,       "MIME media type" },
	{ 0,	                   NULL }
};

static int
parse_attributes(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
	guint8 tag;
	gchar *tag_desc;
	guint16 name_length, value_length;
	proto_tree *as_tree = tree;
	proto_item *tas = NULL;
	int start_offset = offset;
	proto_tree *attr_tree = tree;

	while (IS_DATA_IN_FRAME(offset)) {
		tag = pd[offset];
		tag_desc = val_to_str(tag, tag_vals, "Reserved (0x%02x)");
		if (TAG_TYPE(tag) == TAG_TYPE_DELIMITER) {
			/*
			 * If we had an attribute sequence we were
			 * working on, we're done with it; set its
			 * length to the length of all the stuff
			 * we've done so far.
			 */
			if (tas != NULL)
				proto_item_set_len(tas, offset - start_offset);

			/*
			 * This tag starts a new attribute sequence;
			 * create a new tree under this tag when we see
			 * a non-delimiter tag, under which to put
			 * those attributes.
			 */
			as_tree = NULL;
			attr_tree = tree;

			/*
			 * Remember the offset at which this attribute
			 * sequence started, so we can use it to compute
			 * its length when it's finished.
			 */
			start_offset = offset;

			/*
			 * Now create a new item for this tag.
			 */
			tas = proto_tree_add_text(tree, offset, 1,
			    "%s", tag_desc);
			offset++;
			if (tag == TAG_END_OF_ATTRIBUTES) {
				/*
				 * No more attributes.
				 */
				break;
			}
		} else {
			/*
			 * Value tag - get the name length.
			 */
			if (!BYTES_ARE_IN_FRAME(offset + 1, 2)) {
				/*
				 * We ran past the end of the frame.
				 * Quit (we need to be able to handle
				 * stuff that crosses frames to do more)
				 */
				break;
			}
			name_length = pntohs(&pd[offset + 1]);

			/*
			 * OK, get the value length.
			 */
			if (!BYTES_ARE_IN_FRAME(offset + 1 + 2, name_length)) {
				/*
				 * We ran past the end of the frame.
				 * Quit (we need to be able to handle
				 * stuff that crosses frames to do more)
				 */
				break;
			}
			value_length = pntohs(&pd[offset + 1 + 2 + name_length]);

			/*
			 * OK, does the value run past the end of the
			 * frame?
			 */
			if (!BYTES_ARE_IN_FRAME(offset + 1 + 2 + name_length + 2,
			    value_length)) {
				/*
				 * We ran past the end of the frame.
				 * Quit (we need to be able to handle
				 * stuff that crosses frames to do more)
				 */
				break;
			}
			if (as_tree == NULL) {
				/*
				 * OK, there's an attribute to hang
				 * under a delimiter tag, but we don't
				 * have a tree for that tag yet; create
				 * a tree.
				 */
				as_tree = proto_item_add_subtree(tas,
				    ett_ipp_as);
				attr_tree = as_tree;
			}

			switch (TAG_TYPE(tag)) {

			case TAG_TYPE_INTEGER:
				if (name_length != 0) {
					/*
					 * This is an attribute, not
					 * an additional value, so
					 * start a tree for it.
					 */
					attr_tree = add_integer_tree(as_tree,
					    pd, offset, name_length,
					    value_length);
				}
				add_integer_value(tag, tag_desc, attr_tree, pd,
				    offset, name_length, value_length);
				break;

			case TAG_TYPE_OCTETSTRING:
				if (name_length != 0) {
					/*
					 * This is an attribute, not
					 * an additional value, so
					 * start a tree for it.
					 */
					attr_tree = add_octetstring_tree(as_tree,
					    pd, offset, name_length,
					    value_length);
				}
				add_octetstring_value(tag, tag_desc,
				    attr_tree, pd, offset, name_length,
				    value_length);
				break;

			case TAG_TYPE_CHARSTRING:
				if (name_length != 0) {
					/*
					 * This is an attribute, not
					 * an additional value, so
					 * start a tree for it.
					 */
					attr_tree = add_charstring_tree(as_tree,
					    pd, offset, name_length,
					    value_length);
				}
				add_charstring_value(tag, tag_desc,
				    attr_tree, pd, offset, name_length,
				    value_length);
				break;
			}
			offset += 1 + 2 + name_length + 2 + value_length;
		}
	}

	return offset;
}

static proto_tree *
add_integer_tree(proto_tree *tree, const u_char *pd, int offset,
    guint name_length, guint value_length)
{
	proto_item *ti;

	if (value_length != 4) {
		ti = proto_tree_add_text(tree, offset,
		    1 + 2 + name_length + 2 + value_length,
		    "%.*s: Invalid integer (length is %u, should be 4)",
		    name_length, &pd[offset + 1 + 2],
		    value_length);
	} else {
		ti = proto_tree_add_text(tree, offset,
		    1 + 2 + name_length + 2 + value_length,
		    "%.*s: %u",
		    name_length, &pd[offset + 1 + 2],
		    pntohl(&pd[1 + 2 + name_length + 2]));
	}
	return proto_item_add_subtree(ti, ett_ipp_attr);
}

static void
add_integer_value(guint tag, gchar *tag_desc, proto_tree *tree,
    const u_char *pd, int offset, guint name_length, guint value_length)
{
	offset = add_value_head(tag, tag_desc, tree, pd, offset,
	    name_length, value_length);
	if (value_length == 4) {
		proto_tree_add_text(tree, offset, value_length,
		    "Value: %u", pntohl(&pd[1 + 2 + name_length + 2]));
	}
}

static proto_tree *
add_octetstring_tree(proto_tree *tree, const u_char *pd, int offset,
    guint name_length, guint value_length)
{
	proto_item *ti;

	ti = proto_tree_add_text(tree, offset,
	    1 + 2 + name_length + 2 + value_length,
	    "%.*s: %s",
	    name_length,
	    &pd[offset + 1 + 2]);
	    bytes_to_str(&pd[offset + 1 + 2 + name_length + 2], value_length);
	return proto_item_add_subtree(ti, ett_ipp_attr);
}

static void
add_octetstring_value(guint tag, gchar *tag_desc, proto_tree *tree,
    const u_char *pd, int offset, guint name_length, guint value_length)
{
	offset = add_value_head(tag, tag_desc, tree, pd, offset,
	    name_length, value_length);
	proto_tree_add_text(tree, offset, value_length,
	    "Value: %s", bytes_to_str(&pd[offset], value_length));
}

static proto_tree *
add_charstring_tree(proto_tree *tree, const u_char *pd, int offset,
    guint name_length, guint value_length)
{
	proto_item *ti;

	ti = proto_tree_add_text(tree, offset,
	    1 + 2 + name_length + 2 + value_length,
	    "%.*s: %.*s",
	    name_length, &pd[offset + 1 + 2],
	    value_length, &pd[offset + 1 + 2 + name_length + 2]);
	return proto_item_add_subtree(ti, ett_ipp_attr);
}

static void
add_charstring_value(guint tag, gchar *tag_desc, proto_tree *tree,
    const u_char *pd, int offset, guint name_length, guint value_length)
{
	offset = add_value_head(tag, tag_desc, tree, pd, offset,
	    name_length, value_length);
	proto_tree_add_text(tree, offset, value_length,
	    "Value: %.*s", value_length, &pd[offset]);
}

static int
add_value_head(guint tag, gchar *tag_desc, proto_tree *tree,
    const u_char *pd, int offset, guint name_length, guint value_length)
{
	proto_tree_add_text(tree, offset, 1, "Tag: %s", tag_desc);
	offset += 1;
	proto_tree_add_text(tree, offset, 2, "Name length: %u",
	    name_length);
	offset += 2;
	if (name_length != 0) {
		proto_tree_add_text(tree, offset, name_length,
		    "Name: %.*s", name_length, &pd[offset]);
	}
	offset += name_length;
	proto_tree_add_text(tree, offset, 2, "Value length: %u",
	    value_length);
	offset += 2;
	return offset;
}

void
proto_register_ipp(void)
{
/*        static hf_register_info hf[] = {
                { &variable,
                { "Name",           "ipp.abbreviation", TYPE, VALS_POINTER }},
        };*/
	static gint *ett[] = {
		&ett_ipp,
		&ett_ipp_as,
		&ett_ipp_attr,
	};

        proto_ipp = proto_register_protocol("Internet Printing Protocol", "ipp");
 /*       proto_register_field_array(proto_ipp, hf, array_length(hf));*/
	proto_register_subtree_array(ett, array_length(ett));
}
