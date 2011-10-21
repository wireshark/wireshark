/* packet-ipp.c
 * Routines for IPP packet disassembly
 *
 * Guy Harris <guy@alum.mit.edu>
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
#include "config.h"
#endif

#include <string.h>
#include <ctype.h>

#include <glib.h>
#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/to_str.h>
#include "packet-http.h"

static int proto_ipp = -1;
static int hf_ipp_timestamp = -1;

static gint ett_ipp = -1;
static gint ett_ipp_as = -1;
static gint ett_ipp_attr = -1;

static dissector_handle_t data_handle;

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
#define IDLE            0x3
#define PROCESSING      0x4
#define STOPPED         0x5

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

/* Printer States */
static const value_string printer_state_vals[] = {
    { IDLE,         "Idle" },
    { PROCESSING,   "Processing" },
    { STOPPED,      "Stopped" },
    { 0,            NULL }
};

/* Job States */
static const value_string job_state_vals[] = {
    { 3,            "Pending" },
    { 4,            "Pending - Job Held" },
    { 5,            "Processing" },
    { 6,            "Processing - Job Stopped" },
    { 7,            "Canceled" },
    { 8,            "Aborted" },
    { 9,            "Completed" },
    { 0,            NULL }
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

static int parse_attributes(tvbuff_t *tvb, int offset, proto_tree *tree);
static proto_tree *add_integer_tree(proto_tree *tree, tvbuff_t *tvb,
    int offset, int name_length, int value_length, guint8 tag);
static void add_integer_value(const gchar *tag_desc, proto_tree *tree,
    tvbuff_t *tvb, int offset, int name_length, int value_length, guint8 tag);
static proto_tree *add_octetstring_tree(proto_tree *tree, tvbuff_t *tvb,
    int offset, int name_length, int value_length);
static void add_octetstring_value(const gchar *tag_desc, proto_tree *tree,
    tvbuff_t *tvb, int offset, int name_length, int value_length);
static proto_tree *add_charstring_tree(proto_tree *tree, tvbuff_t *tvb,
    int offset, int name_length, int value_length);
static void add_charstring_value(const gchar *tag_desc, proto_tree *tree,
    tvbuff_t *tvb, int offset, int name_length, int value_length);
static int add_value_head(const gchar *tag_desc, proto_tree *tree,
    tvbuff_t *tvb, int offset, int name_length, int value_length, char **name_val);

static void
dissect_ipp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *ipp_tree;
	proto_item *ti;
	int offset = 0;
	gboolean is_request = (pinfo->destport == pinfo->match_port);
	    /* XXX - should this be based on the HTTP header? */
	guint16 status_code;
	const gchar *status_fmt;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "IPP");
	if (check_col(pinfo->cinfo, COL_INFO)) {
		if (is_request)
			col_set_str(pinfo->cinfo, COL_INFO, "IPP request");
		else
			col_set_str(pinfo->cinfo, COL_INFO, "IPP response");
	}

	if (tree) {
		ti = proto_tree_add_item(tree, proto_ipp, tvb, offset, -1,
		    ENC_NA);
		ipp_tree = proto_item_add_subtree(ti, ett_ipp);

		proto_tree_add_text(ipp_tree, tvb, offset, 2, "Version: %u.%u",
		    tvb_get_guint8(tvb, offset),
		    tvb_get_guint8(tvb, offset + 1));
		offset += 2;

		if (is_request) {
			proto_tree_add_text(ipp_tree, tvb, offset, 2, "Operation-id: %s",
			    val_to_str(tvb_get_ntohs(tvb, offset), operation_vals,
			        "Unknown (0x%04x)"));
		} else {
			status_code = tvb_get_ntohs(tvb, offset);
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
			proto_tree_add_text(ipp_tree, tvb, offset, 2, "Status-code: %s",
			    val_to_str(status_code, status_vals, status_fmt));
		}
		offset += 2;

		proto_tree_add_text(ipp_tree, tvb, offset, 4, "Request ID: %u",
		    tvb_get_ntohl(tvb, offset));
		offset += 4;

		offset = parse_attributes(tvb, offset, ipp_tree);

		if (tvb_offset_exists(tvb, offset)) {
			call_dissector(data_handle,
			    tvb_new_subset_remaining(tvb, offset), pinfo,
			    ipp_tree);
		}
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
parse_attributes(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	guint8 tag;
	const gchar *tag_desc;
	int name_length, value_length;
	proto_tree *as_tree = tree;
	proto_item *tas = NULL;
	int start_offset = offset;
	proto_tree *attr_tree = tree;

	while (tvb_offset_exists(tvb, offset)) {
		tag = tvb_get_guint8(tvb, offset);
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
			tas = proto_tree_add_text(tree, tvb, offset, 1,
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
			name_length = tvb_get_ntohs(tvb, offset + 1);

			/*
			 * OK, get the value length.
			 */
			value_length = tvb_get_ntohs(tvb, offset + 1 + 2 + name_length);

			/*
			 * OK, does the value run past the end of the
			 * frame?
			 */
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
					    tvb, offset, name_length,
					    value_length, tag);
				}
				add_integer_value(tag_desc, attr_tree, tvb,
				    offset, name_length, value_length, tag);
				break;

			case TAG_TYPE_OCTETSTRING:
				if (name_length != 0) {
					/*
					 * This is an attribute, not
					 * an additional value, so
					 * start a tree for it.
					 */
					attr_tree = add_octetstring_tree(as_tree,
					    tvb, offset, name_length,
					    value_length);
				}
				add_octetstring_value(tag_desc, attr_tree, tvb,
				    offset, name_length, value_length);
				break;

			case TAG_TYPE_CHARSTRING:
				if (name_length != 0) {
					/*
					 * This is an attribute, not
					 * an additional value, so
					 * start a tree for it.
					 */
					attr_tree = add_charstring_tree(as_tree,
					    tvb, offset, name_length,
					    value_length);
				}
				add_charstring_value(tag_desc, attr_tree, tvb,
				    offset, name_length, value_length);
				break;
			}
			offset += 1 + 2 + name_length + 2 + value_length;
		}
	}

	return offset;
}

static const value_string bool_vals[] = {
	{ 0x00, "false" },
	{ 0x01, "true" },
	{ 0,    NULL }
};

static proto_tree *
add_integer_tree(proto_tree *tree, tvbuff_t *tvb, int offset,
    int name_length, int value_length, guint8 tag)
{
	proto_item *ti;
	guint8 bool_val;

	switch (tag) {

	case TAG_BOOLEAN:
		if (value_length != 1) {
			ti = proto_tree_add_text(tree, tvb, offset,
			    1 + 2 + name_length + 2 + value_length,
			    "%s: Invalid boolean (length is %u, should be 1)",
			    tvb_format_text(tvb, offset + 1 + 2, name_length),
			    value_length);
		} else {
			bool_val = tvb_get_guint8(tvb,
			    offset + 1 + 2 + name_length + 2);
			ti = proto_tree_add_text(tree, tvb, offset,
			    1 + 2 + name_length + 2 + value_length,
			    "%s: %s",
			    tvb_format_text(tvb, offset + 1 + 2, name_length),
			    val_to_str(bool_val, bool_vals, "Unknown (0x%02x)"));
		}
		break;

	case TAG_INTEGER:
	case TAG_ENUM:
		if (value_length != 4) {
			ti = proto_tree_add_text(tree, tvb, offset,
			    1 + 2 + name_length + 2 + value_length,
			    "%s: Invalid integer (length is %u, should be 4)",
			    tvb_format_text(tvb, offset + 1 + 2, name_length),
			    value_length);
		} else {
			const char *name_val;
			/* Some fields in IPP are really unix timestamps but IPP
			 * transports these as 4 byte integers.
			 * A simple heuristic to make the display of these fields
		 	 * more human readable is to assume that if the field name
		 	 * ends in '-time' then assume they are timestamps instead
		 	 * of integers.
		 	 */
			name_val=tvb_get_ptr(tvb, offset + 1 + 2, name_length);
			if( (name_length > 5) && name_val && !tvb_memeql(tvb, offset + 1 + 2 + name_length - 5, "-time", 5)){
				ti = proto_tree_add_text(tree, tvb, offset,
				    1 + 2 + name_length + 2 + value_length,
				    "%s: %s",
				    format_text(name_val, name_length),
				    abs_time_secs_to_str(tvb_get_ntohl(tvb, offset + 1 + 2 + name_length + 2), ABSOLUTE_TIME_LOCAL, TRUE));

			}
            else if((name_length > 5) && name_val && !tvb_memeql(tvb, offset + 1 + 2, "printer-state", 13)){
				ti = proto_tree_add_text(tree, tvb, offset,
				    1 + 2 + name_length + 2 + value_length,
				    "%s: %s",
				    format_text(name_val, name_length),
				    val_to_str(tvb_get_ntohl(tvb, offset + 1 + 2 + name_length + 2), printer_state_vals, "Unknown Printer State"));
            }
            else if((name_length > 5) && name_val && !tvb_memeql(tvb, offset + 1 + 2, "job-state", 9)){
				ti = proto_tree_add_text(tree, tvb, offset,
				    1 + 2 + name_length + 2 + value_length,
				    "%s: %s",
				    format_text(name_val, name_length),
				    val_to_str(tvb_get_ntohl(tvb, offset + 1 + 2 + name_length + 2), job_state_vals, "Unknown Job State"));
            }
            else {
				ti = proto_tree_add_text(tree, tvb, offset,
				    1 + 2 + name_length + 2 + value_length,
				    "%s: %u",
				    format_text(name_val, name_length),
				    tvb_get_ntohl(tvb, offset + 1 + 2 + name_length + 2));
			}
		}
		break;

	default:
		ti = proto_tree_add_text(tree, tvb, offset,
		    1 + 2 + name_length + 2 + value_length,
		    "%s: Unknown integer type 0x%02x",
		    tvb_format_text(tvb, offset + 1 + 2, name_length),
		    tag);
		break;
	}
	return proto_item_add_subtree(ti, ett_ipp_attr);
}

static void
add_integer_value(const gchar *tag_desc, proto_tree *tree, tvbuff_t *tvb,
    int offset, int name_length, int value_length, guint8 tag)
{
	guint8 bool_val;
	char *name_val;

	offset = add_value_head(tag_desc, tree, tvb, offset, name_length,
	    value_length, &name_val);

	switch (tag) {

	case TAG_BOOLEAN:
		if (value_length == 1) {
			bool_val = tvb_get_guint8(tvb, offset);
			proto_tree_add_text(tree, tvb, offset, value_length,
			    "Value: %s",
			    val_to_str(bool_val, bool_vals, "Unknown (0x%02x)"));
		}
		break;

	case TAG_INTEGER:
	case TAG_ENUM:
		/* Some fields in IPP are really unix timestamps but IPP
		 * transports these as 4 byte integers.
		 * A simple heuristic to make the display of these fields
		 * more human readable is to assume that if the field name
		 * ends in '-time' then assume they are timestamps instead
		 * of integers.
		 */
		if (value_length == 4) {
			if( (name_length > 5) && name_val && !strcmp(name_val+name_length-5, "-time")){
			 	nstime_t ns;

				ns.secs=tvb_get_ntohl(tvb, offset);
				ns.nsecs=0;
				proto_tree_add_time(tree, hf_ipp_timestamp, tvb, offset, 4, &ns);
			}
            else if((name_length > 5) && name_val && !strcmp(name_val, "printer-state")){
                guint32 printer_state_reason;

                printer_state_reason = tvb_get_ntohl(tvb, offset);
                proto_tree_add_text(tree, tvb, offset, value_length, "Value: %s (%u)", val_to_str(printer_state_reason, printer_state_vals, "Unknown Printer State (0x%02x)"), printer_state_reason);
            }
            else if((name_length > 5) && name_val && !strcmp(name_val, "job-state")){
                guint32 job_state_reason;

                job_state_reason = tvb_get_ntohl(tvb, offset);
                proto_tree_add_text(tree, tvb, offset, value_length, "Value: %s (%u)", val_to_str(job_state_reason, job_state_vals, "Unknown Job State (0x%02x)"), job_state_reason);
            }
            else{
			    proto_tree_add_text(tree, tvb, offset, value_length,
				        "Value: %u", tvb_get_ntohl(tvb, offset));
			}
		}
		break;
	}
}

static proto_tree *
add_octetstring_tree(proto_tree *tree, tvbuff_t *tvb, int offset,
    int name_length, int value_length)
{
	proto_item *ti;

	ti = proto_tree_add_text(tree, tvb, offset,
	    1 + 2 + name_length + 2 + value_length,
	    "%s: %s",
	    tvb_format_text(tvb, offset + 1 + 2, name_length),
	    tvb_bytes_to_str(tvb, offset + 1 + 2 + name_length + 2, value_length));
	return proto_item_add_subtree(ti, ett_ipp_attr);
}

static void
add_octetstring_value(const gchar *tag_desc, proto_tree *tree, tvbuff_t *tvb,
    int offset, int name_length, int value_length)
{
	offset = add_value_head(tag_desc, tree, tvb, offset, name_length,
	    value_length, NULL);
	proto_tree_add_text(tree, tvb, offset, value_length,
	    "Value: %s", tvb_bytes_to_str(tvb, offset, value_length));
}

static proto_tree *
add_charstring_tree(proto_tree *tree, tvbuff_t *tvb, int offset,
    int name_length, int value_length)
{
	proto_item *ti;

	ti = proto_tree_add_text(tree, tvb, offset,
	    1 + 2 + name_length + 2 + value_length,
	    "%s: %s",
	    tvb_format_text(tvb, offset + 1 + 2, name_length),
	    tvb_format_text(tvb, offset + 1 + 2 + name_length + 2, value_length));
	return proto_item_add_subtree(ti, ett_ipp_attr);
}

static void
add_charstring_value(const gchar *tag_desc, proto_tree *tree, tvbuff_t *tvb,
    int offset, int name_length, int value_length)
{
	offset = add_value_head(tag_desc, tree, tvb, offset, name_length,
	    value_length, NULL);
	proto_tree_add_text(tree, tvb, offset, value_length,
	    "Value: %s", tvb_format_text(tvb, offset, value_length));
}

/* If name_val is !NULL then return the pointer to an emem allocated string in
 * this variable.
 */
static int
add_value_head(const gchar *tag_desc, proto_tree *tree, tvbuff_t *tvb,
    int offset, int name_length, int value_length, char **name_val)
{
	proto_tree_add_text(tree, tvb, offset, 1, "Tag: %s", tag_desc);
	offset += 1;
	proto_tree_add_text(tree, tvb, offset, 2, "Name length: %u",
	    name_length);
	offset += 2;
	if (name_length != 0) {
		guint8 *nv;
		nv = tvb_get_ephemeral_string(tvb, offset, name_length);
		proto_tree_add_text(tree, tvb, offset, name_length,
		    "Name: %s", format_text(nv, name_length));
		if(name_val){
			*name_val=nv;
		}
	}
	offset += name_length;
	proto_tree_add_text(tree, tvb, offset, 2, "Value length: %u",
	    value_length);
	offset += 2;
	return offset;
}

void
proto_register_ipp(void)
{
        static hf_register_info hf[] = {
                { &hf_ipp_timestamp,
                  { "Time", "ipp.timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
                    NULL, 0, NULL, HFILL }},
        };
	static gint *ett[] = {
		&ett_ipp,
		&ett_ipp_as,
		&ett_ipp_attr,
	};

        proto_ipp = proto_register_protocol("Internet Printing Protocol",
	    "IPP", "ipp");
        proto_register_field_array(proto_ipp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_ipp(void)
{
	dissector_handle_t ipp_handle;

	/*
	 * Register ourselves as running atop HTTP and using port 631.
	 */
	ipp_handle = create_dissector_handle(dissect_ipp, proto_ipp);
	http_dissector_add(631, ipp_handle);
	dissector_add_string("media_type", "application/ipp", ipp_handle);
        data_handle = find_dissector("data");
}
