/*
XXX  Fixme : shouldnt show [malformed frame] for long packets
*/

/* packet-smb-pipe.c
 * Routines for SMB named pipe packet dissection
 * Copyright 1999, Richard Sharpe <rsharpe@ns.aus.com>
 * significant rewrite to tvbuffify the dissector, Ronnie Sahlberg and
 * Guy Harris 2001
 *
 * $Id: packet-smb-pipe.c,v 1.32 2001/08/27 08:42:26 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-pop.c
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

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <time.h>
#include <string.h>
#include <glib.h>
#include <ctype.h>
#include "packet.h"
#include "conversation.h"
#include "smb.h"
#include "packet-smb-pipe.h"
#include "packet-smb-browse.h"

static int proto_smb_lanman = -1;
static int hf_function_code = -1;
static int hf_param_desc = -1;
static int hf_return_desc = -1;
static int hf_not_implemented = -1;
static int hf_detail_level = -1;
static int hf_recv_buf_len = -1;
static int hf_response_to = -1;
static int hf_continuation_from = -1;
static int hf_status = -1;
static int hf_convert = -1;
static int hf_ecount = -1;
static int hf_acount = -1;
static int hf_share_name = -1;
static int hf_share_type = -1;
static int hf_share_comment = -1;
static int hf_share_permissions = -1;
static int hf_share_max_uses = -1;
static int hf_share_current_uses = -1;
static int hf_server_name = -1;
static int hf_server_major = -1;
static int hf_server_minor = -1;
static int hf_server_comment = -1;
static int hf_abytes = -1;
static int hf_current_time = -1;
static int hf_msecs = -1;
static int hf_hour = -1;
static int hf_minute = -1;
static int hf_second = -1;
static int hf_hundredths = -1;
static int hf_tzoffset = -1;
static int hf_timeinterval = -1;
static int hf_day = -1;
static int hf_month = -1;
static int hf_year = -1;
static int hf_weekday = -1;
static int hf_computer_name = -1;
static int hf_user_name = -1;
static int hf_workstation_domain = -1;
static int hf_workstation_major = -1;
static int hf_workstation_minor = -1;
static int hf_logon_domain = -1;
static int hf_other_domains = -1;
static int hf_password = -1;
static int hf_workstation_name = -1;
static int hf_ustruct_size = -1;
static int hf_logon_code = -1;
static int hf_privilege_level = -1;
static int hf_operator_privileges = -1;
static int hf_num_logons = -1;
static int hf_bad_pw_count = -1;
static int hf_last_logon = -1;
static int hf_last_logoff = -1;
static int hf_logoff_time = -1;
static int hf_kickoff_time = -1;
static int hf_password_age = -1;
static int hf_password_can_change = -1;
static int hf_password_must_change = -1;
static int hf_script_path = -1;
static int hf_logoff_code = -1;
static int hf_duration = -1;
static int hf_user_comment = -1;
static int hf_full_name = -1;
static int hf_homedir = -1;
static int hf_parameters = -1;
static int hf_logon_server = -1;
static int hf_country_code = -1;
static int hf_workstations = -1;
static int hf_max_storage = -1;
static int hf_units_per_week = -1;
static int hf_logon_hours = -1;
static int hf_code_page = -1;
static int hf_new_password = -1;
static int hf_old_password = -1;

static gint ett_lanman = -1;
static gint ett_lanman_servers = -1;
static gint ett_lanman_server = -1;
static gint ett_lanman_shares = -1;
static gint ett_lanman_share = -1;

/*
 * See
 *
 *	ftp://ftp.microsoft.com/developr/drg/CIFS/cifsrap2.txt
 *
 * among other documents.
 */

static const value_string status_vals[] = {
	{0,	"Success"},
	{5,	"User has insufficient privilege"},
	{65,	"Network access is denied"},
	{86,	"The specified password is invalid"},
	{SMBE_moredata, "Additional data is available"},
	{2114,	"Service is not running on the remote computer"},
	{2123,	"Supplied buffer is too small"},
	{2141,	"Server is not configured for transactions (IPC$ not shared)"},
	{2212,  "An error occurred while loading or running the logon script"},
	{2214,  "The logon was not validated by any server"},
	{2217,  "The logon server is running an older software version"},
	{2221,  "The user name was not found"},
	{2240,  "The user is not allowed to logon from this computer"},
	{2241,  "The user is not allowed to logon at this time"},
	{2242,  "The user password has expired"},
	{2243,  "The password cannot be changed"},
	{2246,  "The password is too short"},
	{0,     NULL}
};

static const value_string share_type_vals[] = {
        {0, "Directory tree"},
        {1, "Printer queue"},
        {2, "Communications device"},
        {3, "IPC"},
        {0, NULL}
};

static const value_string privilege_vals[] = {
	{0, "Guest"},
	{1, "User"},
	{2, "Administrator"},
	{0, NULL}
};

static const value_string op_privilege_vals[] = {
	{0, "Print operator"},
	{1, "Communications operator"},
	{2, "Server operator"},
	{3, "Accounts operator"},
	{0, NULL}
};

static const value_string weekday_vals[] = {
	{0, "Sunday"},
	{1, "Monday"},
	{2, "Tuesday"},
	{3, "Wednesday"},
	{4, "Thursday"},
	{5, "Friday"},
	{6, "Saturday"},
	{0, NULL}
};

static int
not_implemented(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
	proto_tree_add_item(tree, hf_not_implemented, tvb, offset, tvb_length_remaining(tvb, offset), TRUE);

	return offset+tvb_length_remaining(tvb,offset);
}

static int
add_string_pointer(tvbuff_t *tvb, proto_tree *tree, int offset, int convert,
    int hf_index)
{
	int cptr;
	gint string_len;

	/* pointer to string */
	cptr = (tvb_get_letohl(tvb, offset)&0xffff)-convert;
	offset += 4;

	/* string */
	if (tvb_offset_exists(tvb, cptr) &&
	    (string_len = tvb_strnlen(tvb, cptr, -1)) != -1) {
		proto_tree_add_item(tree, hf_index, tvb, cptr,
		    string_len + 1, TRUE);
	} else {
		proto_tree_add_text(tree, tvb, 0, 0,
		    "%s: <String goes past end of frame>",
		    proto_registrar_get_name(hf_index));
	}

	return offset;
}

static int
add_byte_array_pointer(tvbuff_t *tvb, proto_tree *tree, int offset, int len,
    int convert, int hf_index)
{
	int cptr;

	/* pointer to string */
	cptr = (tvb_get_letohl(tvb, offset)&0xffff)-convert;
	offset += 4;

	/* string */
	proto_tree_add_item(tree, hf_index, tvb, cptr, len, TRUE);

	return offset;
}

/*
 * Sigh.  This is for handling Microsoft's annoying almost-UNIX-time-but-
 * it's-local-time-not-UTC time.
 */
static time_t
localtime_to_utc(time_t local)
{
	struct tm *tmp;

	/*
	 * Run it through "gmtime()" to break it down, and then run it
	 * through "mktime()" to put it back together as UTC.
	 */
	tmp = gmtime(&local);
	tmp->tm_isdst = -1;	/* we don't know if it's DST or not */
	return mktime(tmp);
}

static int
netshareenum_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    struct smb_request_val *request_val, int offset)
{
	/* detail level */
	proto_tree_add_item(tree, hf_detail_level, tvb, offset, 2, TRUE);
	offset += 2;

	/* receiver buffer length */
	proto_tree_add_item(tree, hf_recv_buf_len, tvb, offset, 2, TRUE);
	offset += 2;

	return offset;
}

static int
netshareenum_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    struct smb_request_val *request_val, int offset, guint16 status,
    int convert)
{
	struct smb_info *smb_info = pinfo->private;
	proto_item *it = NULL;
	proto_tree *tr = NULL;
	guint16 acount, ecount;
	int i;

	/* entry count */
	ecount = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint(tree, hf_ecount, tvb, offset, 2, ecount);
	offset += 2;

	/* available count */
	acount = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint(tree, hf_acount, tvb, offset, 2, acount);
	offset += 2;

	if (status != 0 && status != SMBE_moredata)
		return offset;

	/* The rest is in the data section. */
	offset = smb_info->data_offset;

	/* create a subtree for all available shares */
	if (tree) {
		it = proto_tree_add_text(tree, tvb, offset,
		    tvb_length_remaining(tvb, offset),
		    "Available Shares");
		tr = proto_item_add_subtree(it, ett_lanman_shares);
	}

	for (i = 0; i < ecount; i++){
		proto_item *si = NULL;
		proto_tree *st = NULL;
		char *share;
		int start_offset = offset;

		share = (char *)tvb_get_ptr(tvb, offset, 13);

		if (tree) {
			si = proto_tree_add_text(tr, tvb, offset,
			    tvb_length_remaining(tvb, offset),
			    "Share %s", share);
			st = proto_item_add_subtree(si, ett_lanman_shares);
		}

		/* share name */
		proto_tree_add_item(st, hf_share_name, tvb, offset, 13, TRUE);
		offset += 13;

		/* pad byte */
		offset += 1;

		/* share type */
		proto_tree_add_item(st, hf_share_type, tvb, offset, 2, TRUE);
		offset += 2;

		/* share comment */
		offset = add_string_pointer(tvb, st, offset, convert,
		    hf_share_comment);

		proto_item_set_len(si, offset-start_offset);
	}

	return offset;
}

static int
netsharegetinfo_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    struct smb_request_val *request_val, int offset)
{
	guint share_name_len;
	guint16 level;

	/* share name */
	share_name_len = tvb_strsize(tvb, offset);
	proto_tree_add_item(tree, hf_share_name, tvb, offset, share_name_len,
	    TRUE);
	offset += share_name_len;

	/* detail level */
	level = tvb_get_letohs(tvb, offset);
	if (!pinfo->fd->flags.visited)
		request_val->last_level = level;	/* remember this for the response */
	proto_tree_add_uint(tree, hf_detail_level, tvb, offset, 2, level);
	offset += 2;

	/* receiver buffer length */
	proto_tree_add_item(tree, hf_recv_buf_len, tvb, offset, 2, TRUE);
	offset += 2;

	return offset;
}

static int
netsharegetinfo_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    struct smb_request_val *request_val, int offset, guint16 status,
    int convert)
{
	struct smb_info *smb_info = pinfo->private;
	guint16 abytes;
	guint16 permissions;
	guint16 max_uses;

	/* available bytes */
	abytes = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint(tree, hf_abytes, tvb, offset, 2, abytes);
	offset += 2;

	if (status != 0 && status != SMBE_moredata)
		return offset;

	/* XXX - what is this field? */
	proto_tree_add_text(tree, tvb, offset, 2, "Mysterious field: %04x",
	    tvb_get_letohs(tvb, offset));
	offset += 2;

	/* The rest is in the data section. */
	offset = smb_info->data_offset;

	/* share name */
	proto_tree_add_item(tree, hf_share_name, tvb, offset, 13, TRUE);
	offset += 13;

	if (request_val->last_level == 0)
		return offset;	/* that's it, at level 0 */

	/* pad byte */
	offset += 1;

	/* share type */
	proto_tree_add_item(tree, hf_share_type, tvb, offset, 2, TRUE);
	offset += 2;

	/* share comment */
	offset = add_string_pointer(tvb, tree, offset, convert,
	    hf_share_comment);

	if (request_val->last_level == 1)
		return offset;	/* that's it, at level 1 */

	/* share permissions */
	/* XXX - do as bit fields */
	permissions = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint(tree, hf_share_permissions, tvb, offset, 2,
	    permissions);
	offset += 2;

	/* max uses */
	max_uses = tvb_get_letohs(tvb, offset);
	if (max_uses == 0xffff) {	/* -1 */
		proto_tree_add_uint_format(tree, hf_share_max_uses, tvb,
		    offset, 2, max_uses, "Share Max Uses: No limit");
	} else {
		proto_tree_add_uint(tree, hf_share_max_uses, tvb, offset, 2,
		    max_uses);
	}
	offset += 2;

	/* current uses */
	max_uses = tvb_get_letohs(tvb, offset);
	proto_tree_add_item(tree, hf_share_current_uses, tvb, offset, 2, TRUE);
	offset += 2;

	return offset;
}

static int
add_server_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    int offset, int convert, guint16 level)
{
	/* server name */
	proto_tree_add_item(tree, hf_server_name, tvb, offset, 16, TRUE);
	offset += 16;

	if (level) {
		/* major version */
		proto_tree_add_item(tree, hf_server_major, tvb, offset, 1,
		    TRUE);
		offset += 1;

		/* minor version */
		proto_tree_add_item(tree, hf_server_minor, tvb, offset, 1,
		    TRUE);
		offset += 1;

		/* server type flags */
		dissect_smb_server_type_flags(tvb, pinfo, tree, offset, FALSE);
		offset += 4;

		/* server comment */
		offset = add_string_pointer(tvb, tree, offset, convert,
		    hf_server_comment);
	}

	return offset;
}

static int
netservergetinfo_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    struct smb_request_val *request_val, int offset)
{
	guint16 level;

	/* detail level */
	level = tvb_get_letohs(tvb, offset);
	if (!pinfo->fd->flags.visited)
		request_val->last_level = level;	/* remember this for the response */
	proto_tree_add_uint(tree, hf_detail_level, tvb, offset, 2, level);
	offset += 2;

	/* receiver buffer length */
	proto_tree_add_item(tree, hf_recv_buf_len, tvb, offset, 2, TRUE);
	offset += 2;

	return offset;
}

static int
netservergetinfo_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    struct smb_request_val *request_val, int offset, guint16 status,
    int convert)
{
	struct smb_info *smb_info = pinfo->private;
	guint16 abytes;

	/* available bytes */
	abytes = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint(tree, hf_abytes, tvb, offset, 2, abytes);
	offset += 2;

	/* XXX - what is this field? */
	proto_tree_add_text(tree, tvb, offset, 2, "Mysterious field: %04x",
	    tvb_get_letohs(tvb, offset));
	offset += 2;

	if (status != 0 && status != SMBE_moredata)
		return offset;

	/* The rest is in the data section. */
	offset = smb_info->data_offset;

	offset = add_server_info(tvb, pinfo, tree, offset, convert,
	    request_val->last_level);

	return offset;
}

static int
netusergetinfo_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    struct smb_request_val *request_val, int offset)
{
	guint16 level;

	/* detail level */
	level = tvb_get_letohs(tvb, offset);
	if (!pinfo->fd->flags.visited)
		request_val->last_level = level;	/* remember this for the response */
	proto_tree_add_uint(tree, hf_detail_level, tvb, offset, 2, level);
	offset += 2;

	/* receiver buffer length */
	proto_tree_add_item(tree, hf_recv_buf_len, tvb, offset, 2, TRUE);
	offset += 2;

	return offset;
}

static int
netusergetinfo_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    struct smb_request_val *request_val, int offset, guint16 status,
    int convert)
{
	struct smb_info *smb_info = pinfo->private;
	guint16 abytes;
	struct timeval timeval;
	guint16 nlogons;
	guint32 max_storage;

	/* available bytes */
	abytes = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint(tree, hf_abytes, tvb, offset, 2, abytes);
	offset += 2;

	/* XXX - what is this field? */
	proto_tree_add_text(tree, tvb, offset, 2, "Mysterious field: %04x",
	    tvb_get_letohs(tvb, offset));
	offset += 2;

	if (status != 0 && status != SMBE_moredata)
		return offset;

	/* The rest is in the data section. */
	offset = smb_info->data_offset;

	/* user name */
	proto_tree_add_item(tree, hf_user_name, tvb, offset, 21, TRUE);
	offset += 21;

	/* pad1 */
	offset += 1;

	/* user comment */
	offset = add_string_pointer(tvb, tree, offset, convert,
	    hf_user_comment);

	/* full name */
	offset = add_string_pointer(tvb, tree, offset, convert, hf_full_name);

	/* privilege level */
	proto_tree_add_item(tree, hf_privilege_level, tvb, offset, 2, TRUE);
	offset += 2;

	/* operator privileges */
	proto_tree_add_item(tree, hf_operator_privileges, tvb, offset, 4, TRUE);
	offset += 4;

	/* password age */
	timeval.tv_sec = tvb_get_letohl(tvb, offset);
	proto_tree_add_time_format(tree, hf_password_age, tvb, offset, 4,
	    &timeval, "Password Age: %s", time_secs_to_str(timeval.tv_sec));
	offset += 4;

	/* home directory */
	offset = add_string_pointer(tvb, tree, offset, convert, hf_homedir);

	/* parameters */
	offset = add_string_pointer(tvb, tree, offset, convert, hf_parameters);

	timeval.tv_usec = 0;

	/* last logon time */
	timeval.tv_sec = tvb_get_letohl(tvb, offset);
	if (timeval.tv_sec == -1) {
		proto_tree_add_time_format(tree, hf_last_logon, tvb, offset, 4,
		    &timeval, "Last Logon Date/Time: Unknown");
	} else {
		timeval.tv_sec = localtime_to_utc(timeval.tv_sec);
		proto_tree_add_time(tree, hf_last_logon, tvb, offset, 4,
		    &timeval);
	}
	offset += 4;

	/* last logoff time */
	timeval.tv_sec = tvb_get_letohl(tvb, offset);
	if (timeval.tv_sec == -1) {
		proto_tree_add_time_format(tree, hf_last_logoff, tvb, offset, 4,
		    &timeval, "Last Logoff Date/Time: Unknown");
	} else {
		timeval.tv_sec = localtime_to_utc(timeval.tv_sec);
		proto_tree_add_time(tree, hf_last_logoff, tvb, offset, 4,
		    &timeval);
	}
	offset += 4;

	/* bad password count */
	proto_tree_add_item(tree, hf_bad_pw_count, tvb, offset, 2, TRUE);
	offset += 2;

	/* number of logons */
	nlogons = tvb_get_letohs(tvb, offset);
	if (nlogons == 0xffff)	/* -1 */
		proto_tree_add_uint_format(tree, hf_num_logons, tvb, offset, 2,
		    nlogons, "Number of Logons: Unknown");
	else
		proto_tree_add_uint(tree, hf_num_logons, tvb, offset, 2,
		    nlogons);
	offset += 2;

	/* logon server */
	offset = add_string_pointer(tvb, tree, offset, convert,
	    hf_logon_server);

	/* country code */
	/* XXX - we should have a value_string table for these */
	proto_tree_add_item(tree, hf_country_code, tvb, offset, 2, TRUE);
	offset += 2;

	/* workstations */
	offset = add_string_pointer(tvb, tree, offset, convert,
	    hf_workstations);

	/* max storage */
	max_storage = tvb_get_letohl(tvb, offset);
	if (max_storage == 0xffffffff)
		proto_tree_add_uint_format(tree, hf_max_storage, tvb, offset, 4,
		    max_storage, "Max Storage: No limit");
	else
		proto_tree_add_uint(tree, hf_max_storage, tvb, offset, 4,
		    max_storage);
	offset += 4;

	/* units per week */
	proto_tree_add_item(tree, hf_units_per_week, tvb, offset, 2, TRUE);
	offset += 2;

	/* logon hours */
	/* XXX - should actually carve up the bits */
	/* XXX - how do we recognize a null pointer? */
	offset = add_byte_array_pointer(tvb, tree, offset, 21, convert,
	    hf_logon_hours);

	/* code page */
	/* XXX - we should have a value_string table for these */
	proto_tree_add_item(tree, hf_code_page, tvb, offset, 2, TRUE);
	offset += 2;

	return offset;
}

static int
netremotetod_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    struct smb_request_val *request_val, int offset)
{
	/* receiver buffer length */
	proto_tree_add_item(tree, hf_recv_buf_len, tvb, offset, 2, TRUE);
	offset += 2;

	return offset;
}

static int
netremotetod_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    struct smb_request_val *request_val, int offset, guint16 status,
    int convert)
{
	struct timeval timeval;
	gint16 tzoffset;
	guint16 timeinterval;

	if (status != 0 && status != SMBE_moredata)
		return offset;

	/* current time */
	timeval.tv_sec = tvb_get_letohl(tvb, offset);
	timeval.tv_sec = localtime_to_utc(timeval.tv_sec);
	timeval.tv_usec = 0;
	proto_tree_add_time(tree, hf_current_time, tvb, offset, 4, &timeval);
	offset += 4;

	/* msecs since arbitrary point in the past */
	proto_tree_add_item(tree, hf_msecs, tvb, offset, 4, TRUE);
	offset += 4;

	/* hour */
	proto_tree_add_item(tree, hf_hour, tvb, offset, 1, TRUE);
	offset += 1;

	/* minute */
	proto_tree_add_item(tree, hf_minute, tvb, offset, 1, TRUE);
	offset += 1;

	/* second */
	proto_tree_add_item(tree, hf_second, tvb, offset, 1, TRUE);
	offset += 1;

	/* hundredths-of-second */
	proto_tree_add_item(tree, hf_hundredths, tvb, offset, 1, TRUE);
	offset += 1;

	/* time zone offset, in minutes */
	tzoffset = tvb_get_letohs(tvb, offset);
	if (tzoffset < 0) {
		proto_tree_add_int_format(tree, hf_tzoffset, tvb, offset, 2,
		    tzoffset, "Time Zone Offset: %s east of UTC",
		    time_secs_to_str(-tzoffset*60));
	} else if (tzoffset > 0) {
		proto_tree_add_int_format(tree, hf_tzoffset, tvb, offset, 2,
		    tzoffset, "Time Zone Offset: %s west of UTC",
		    time_secs_to_str(tzoffset*60));
	} else {
		proto_tree_add_int_format(tree, hf_tzoffset, tvb, offset, 2,
		    tzoffset, "Time Zone Offset: at UTC");
	}
	offset += 2;

	/* timer resolution */
	timeinterval = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint_format(tree, hf_timeinterval, tvb, offset, 2,
	   timeinterval, "Time Interval: %f seconds", timeinterval*.0001);
	offset += 2;

	/* day */
	proto_tree_add_item(tree, hf_day, tvb, offset, 1, TRUE);
	offset += 1;

	/* month */
	proto_tree_add_item(tree, hf_month, tvb, offset, 1, TRUE);
	offset += 1;

	/* year */
	proto_tree_add_item(tree, hf_year, tvb, offset, 2, TRUE);
	offset += 2;

	/* day of week */
	proto_tree_add_item(tree, hf_weekday, tvb, offset, 1, TRUE);
	offset += 1;

	return offset;
}

static int
netserverenum2_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    struct smb_request_val *request_val, int offset)
{
	guint16 level;

	/* detail level */
	level = tvb_get_letohs(tvb, offset);
	if (!pinfo->fd->flags.visited)
		request_val->last_level = level;	/* remember this for the response */
	proto_tree_add_uint(tree, hf_detail_level, tvb, offset, 2, level);
	offset += 2;

	/* receiver buffer length */
	proto_tree_add_item(tree, hf_recv_buf_len, tvb, offset, 2, TRUE);
	offset += 2;

	/* server type flags */
	dissect_smb_server_type_flags(tvb, pinfo, tree, offset, TRUE);
	offset += 4;

	return offset;
}

static int
netserverenum2_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    struct smb_request_val *request_val, int offset, guint16 status,
    int convert)
{
	struct smb_info *smb_info = pinfo->private;
	guint16 ecount, acount;
	proto_item *it = NULL;
	proto_tree *tr = NULL;
	int i;

	/* entry count */
	ecount = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint(tree, hf_ecount, tvb, offset, 2, ecount);
	offset += 2;

	/* available count */
	acount = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint(tree, hf_acount, tvb, offset, 2, acount);
	offset += 2;

	if (status != 0 && status != SMBE_moredata)
		return offset;

	/* The rest is in the data section. */
	offset = smb_info->data_offset;

	if (tree) {
		it = proto_tree_add_text(tree, tvb, offset,
		    tvb_length_remaining(tvb, offset), "Servers");
		tr = proto_item_add_subtree(it, ett_lanman_servers);
	}

	for (i = 0; i < ecount; i++) {
		proto_item *si = NULL;
		proto_tree *st = NULL;
		char *server;
		int old_offset = offset;

		server = (char *)tvb_get_ptr(tvb, offset, 16);
		if (tree) {
			si = proto_tree_add_text(tr, tvb, offset,
			    request_val->last_level ? 26 : 16,
			    "Server %.16s", server);
			st = proto_item_add_subtree(si, ett_lanman_server);
		}

		offset = add_server_info(tvb, pinfo, st, offset, convert,
		    request_val->last_level);

		proto_item_set_len(si, offset-old_offset);
	}

	return offset;
}

static int
netwkstagetinfo_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    struct smb_request_val *request_val, int offset)
{
	guint16 level;

	/* detail level */
	level = tvb_get_letohs(tvb, offset);
	if (!pinfo->fd->flags.visited)
		request_val->last_level = level;	/* remember this for the response */
	proto_tree_add_uint(tree, hf_detail_level, tvb, offset, 2, level);
	offset += 2;

	/* receiver buffer length */
	proto_tree_add_item(tree, hf_recv_buf_len, tvb, offset, 2, TRUE);
	offset += 2;

	return offset;
}

static int
netwkstagetinfo_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    struct smb_request_val *request_val, int offset, guint16 status,
    int convert)
{
	struct smb_info *smb_info = pinfo->private;
	guint16 abytes;

	/* available bytes */
	abytes = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint(tree, hf_abytes, tvb, offset, 2, abytes);
	offset += 2;

	/* XXX - what is this field? */
	proto_tree_add_text(tree, tvb, offset, 2, "Mysterious field: %04x",
	    tvb_get_letohs(tvb, offset));
	offset += 2;

	if (status != 0 && status != SMBE_moredata)
		return offset;

	/* The rest is in the data section. */
	offset = smb_info->data_offset;

	/* computer name */
	offset = add_string_pointer(tvb, tree, offset, convert,
	    hf_computer_name);

	/* user name */
	offset = add_string_pointer(tvb, tree, offset, convert, hf_user_name);

	/* workstation domain */
	offset = add_string_pointer(tvb, tree, offset, convert,
	    hf_workstation_domain);

	/* major version */
	proto_tree_add_item(tree, hf_workstation_major, tvb, offset, 1, TRUE);
	offset += 1;

	/* minor version */
	proto_tree_add_item(tree, hf_workstation_minor, tvb, offset, 1, TRUE);
	offset += 1;

	/* logon domain */
	offset = add_string_pointer(tvb, tree, offset, convert,
	    hf_logon_domain);

	/* other domains */
	offset = add_string_pointer(tvb, tree, offset, convert,
	    hf_other_domains);

	return offset;
}

static int
netwkstauserlogon_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    struct smb_request_val *request_val, int offset)
{
	guint16 level;

	/* detail level */
	level = tvb_get_letohs(tvb, offset);
	if (!pinfo->fd->flags.visited)
		request_val->last_level = level;	/* remember this for the response */
	proto_tree_add_uint(tree, hf_detail_level, tvb, offset, 2, level);
	offset += 2;

	/* user name */
	proto_tree_add_item(tree, hf_user_name, tvb, offset, 21, TRUE);
	offset += 21;

	/* pad1 */
	offset += 1;

	/* password */
	proto_tree_add_item(tree, hf_password, tvb, offset, 15, TRUE);
	offset += 15;

	/* pad2 */
	offset += 1;

	/* workstation name */
	proto_tree_add_item(tree, hf_workstation_name, tvb, offset, 16, TRUE);
	offset += 16;

	/* size of the above */
	proto_tree_add_item(tree, hf_ustruct_size, tvb, offset, 2, TRUE);
	offset += 2;

	/* receiver buffer length */
	proto_tree_add_item(tree, hf_recv_buf_len, tvb, offset, 2, TRUE);
	offset += 2;

	return offset;
}

static int
netwkstauserlogon_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    struct smb_request_val *request_val, int offset, guint16 status,
    int convert)
{
	struct smb_info *smb_info = pinfo->private;
	guint16 abytes;
	guint16 nlogons;
	struct timeval timeval;

	/* available bytes */
	abytes = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint(tree, hf_abytes, tvb, offset, 2, abytes);
	offset += 2;

	/* XXX - what is this field? */
	proto_tree_add_text(tree, tvb, offset, 2, "Mysterious field: %04x",
	    tvb_get_letohs(tvb, offset));
	offset += 2;

	if (status != 0 && status != SMBE_moredata)
		return offset;

	/* The rest is in the data section. */
	offset = smb_info->data_offset;

	/* logon code */
	proto_tree_add_item(tree, hf_logon_code, tvb, offset, 2, TRUE);
	offset += 2;

	/* user name */
	proto_tree_add_item(tree, hf_user_name, tvb, offset, 21, TRUE);
	offset += 21;

	/* pad1 */
	offset += 1;

	/* privilege level */
	proto_tree_add_item(tree, hf_privilege_level, tvb, offset, 2, TRUE);
	offset += 2;

	/* operator privileges */
	proto_tree_add_item(tree, hf_operator_privileges, tvb, offset, 4, TRUE);
	offset += 4;

	/* number of logons */
	nlogons = tvb_get_letohs(tvb, offset);
	if (nlogons == 0xffff)	/* -1 */
		proto_tree_add_uint_format(tree, hf_num_logons, tvb, offset, 2,
		    nlogons, "Number of Logons: Unknown");
	else
		proto_tree_add_uint(tree, hf_num_logons, tvb, offset, 2,
		    nlogons);
	offset += 2;

	/* bad password count */
	proto_tree_add_item(tree, hf_bad_pw_count, tvb, offset, 2, TRUE);
	offset += 2;

	timeval.tv_usec = 0;

	/* last logon time */
	timeval.tv_sec = tvb_get_letohl(tvb, offset);
	if (timeval.tv_sec == -1) {
		proto_tree_add_time_format(tree, hf_last_logon, tvb, offset, 4,
		    &timeval, "Last Logon Date/Time: Unknown");
	} else {
		timeval.tv_sec = localtime_to_utc(timeval.tv_sec);
		proto_tree_add_time(tree, hf_last_logon, tvb, offset, 4,
		    &timeval);
	}
	offset += 4;

	/* last logoff time */
	timeval.tv_sec = tvb_get_letohl(tvb, offset);
	if (timeval.tv_sec == -1) {
		proto_tree_add_time_format(tree, hf_last_logoff, tvb, offset, 4,
		    &timeval, "Last Logoff Date/Time: Unknown");
	} else {
		timeval.tv_sec = localtime_to_utc(timeval.tv_sec);
		proto_tree_add_time(tree, hf_last_logoff, tvb, offset, 4,
		    &timeval);
	}
	offset += 4;

	/* logoff time */
	timeval.tv_sec = tvb_get_letohl(tvb, offset);
	if (timeval.tv_sec == -1) {
		proto_tree_add_time_format(tree, hf_logoff_time, tvb, offset, 4,
		    &timeval, "Logoff Date/Time: None");
	} else {
		timeval.tv_sec = localtime_to_utc(timeval.tv_sec);
		proto_tree_add_time(tree, hf_logoff_time, tvb, offset, 4,
		    &timeval);
	}
	offset += 4;

	/* kickoff time */
	timeval.tv_sec = tvb_get_letohl(tvb, offset);
	if (timeval.tv_sec == -1) {
		proto_tree_add_time_format(tree, hf_kickoff_time, tvb, offset, 4,
		    &timeval, "Kickoff Date/Time: None");
	} else {
		timeval.tv_sec = localtime_to_utc(timeval.tv_sec);
		proto_tree_add_time(tree, hf_kickoff_time, tvb, offset, 4,
		    &timeval);
	}
	offset += 4;

	/* password age */
	timeval.tv_sec = tvb_get_letohl(tvb, offset);
	proto_tree_add_time_format(tree, hf_password_age, tvb, offset, 4,
	    &timeval, "Password Age: %s", time_secs_to_str(timeval.tv_sec));
	offset += 4;

	/* date/time when password can change */
	timeval.tv_sec = tvb_get_letohl(tvb, offset);
	if (timeval.tv_sec == -1) {
		proto_tree_add_time_format(tree, hf_password_can_change, tvb, offset, 4,
		    &timeval, "Password Can Change: Never");
	} else {
		timeval.tv_sec = localtime_to_utc(timeval.tv_sec);
		proto_tree_add_time(tree, hf_password_can_change, tvb, offset, 4,
		    &timeval);
	}
	offset += 4;

	/* date/time when password must change */
	timeval.tv_sec = tvb_get_letohl(tvb, offset);
	if (timeval.tv_sec == -1) {
		proto_tree_add_time_format(tree, hf_password_must_change, tvb, offset, 4,
		    &timeval, "Password Must Change: Never");
	} else {
		timeval.tv_sec = localtime_to_utc(timeval.tv_sec);
		proto_tree_add_time(tree, hf_password_must_change, tvb, offset, 4,
		    &timeval);
	}
	offset += 4;

	/* computer where user is logged on */
	offset = add_string_pointer(tvb, tree, offset, convert,
	    hf_server_name);

	/* domain in which user is logged on */
	offset = add_string_pointer(tvb, tree, offset, convert,
	    hf_logon_domain);

	/* pathname of user's login script */
	offset = add_string_pointer(tvb, tree, offset, convert,
	    hf_script_path);

	/* reserved */
	proto_tree_add_text(tree, tvb, offset, 4, "Reserved: %08x",
	    tvb_get_letohl(tvb, offset));
	offset += 4;

	return offset;
}

static int
netwkstauserlogoff_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    struct smb_request_val *request_val, int offset)
{
	/* user name */
	proto_tree_add_item(tree, hf_user_name, tvb, offset, 21, TRUE);
	offset += 21;

	/* pad1 */
	offset += 1;

	/* workstation name */
	proto_tree_add_item(tree, hf_workstation_name, tvb, offset, 16, TRUE);
	offset += 16;

	return offset;
}

static int
netwkstauserlogoff_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    struct smb_request_val *request_val, int offset, guint16 status,
    int convert)
{
	struct smb_info *smb_info = pinfo->private;
	guint16 abytes;
	guint16 nlogons;
	struct timeval timeval;

	/* available bytes */
	abytes = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint(tree, hf_abytes, tvb, offset, 2, abytes);
	offset += 2;

	/* XXX - what is this field? */
	proto_tree_add_text(tree, tvb, offset, 2, "Mysterious field: %04x",
	    tvb_get_letohs(tvb, offset));
	offset += 2;

	if (status != 0 && status != SMBE_moredata)
		return offset;

	/* The rest is in the data section. */
	offset = smb_info->data_offset;

	/* logoff code */
	proto_tree_add_item(tree, hf_logoff_code, tvb, offset, 2, TRUE);
	offset += 2;

	/* duration */
	timeval.tv_sec = tvb_get_letohl(tvb, offset);
	timeval.tv_usec = 0;
	proto_tree_add_time_format(tree, hf_duration, tvb, offset, 4,
	    &timeval, "Duration of Session: %s", time_secs_to_str(timeval.tv_sec));
	offset += 4;

	/* number of logons */
	nlogons = tvb_get_letohs(tvb, offset);
	if (nlogons == 0xffff)	/* -1 */
		proto_tree_add_uint_format(tree, hf_num_logons, tvb, offset, 2,
		    nlogons, "Number of Logons: Unknown");
	else
		proto_tree_add_uint(tree, hf_num_logons, tvb, offset, 2,
		    nlogons);
	offset += 2;

	return offset;
}

static int
samoemchangepassword_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    struct smb_request_val *request_val, int offset)
{
	struct smb_info *smb_info = pinfo->private;
	guint user_name_len;

	/* user name */
	user_name_len = tvb_strsize(tvb, offset);
	proto_tree_add_item(tree, hf_user_name, tvb, offset, user_name_len,
	    TRUE);
	offset += user_name_len;

	/* new password */
	proto_tree_add_item(tree, hf_new_password, tvb,
	    smb_info->data_offset, 516, TRUE);

	/* old password */
	proto_tree_add_item(tree, hf_old_password, tvb,
	    smb_info->data_offset + 516, 16, TRUE);

	return offset;
}

static int
samoemchangepassword_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    struct smb_request_val *request_val, int offset, guint16 status,
    int convert)
{
	/* nothing in this reply */
	return offset;
}

#define LANMAN_NETSHAREENUM		0
#define LANMAN_NETSHAREGETINFO		1
#define LANMAN_NETSERVERGETINFO		13
#define LANMAN_NETGROUPGETUSERS		52
#define LANMAN_NETUSERGETINFO		56
#define LANMAN_NETUSERGETGROUPS		59
#define LANMAN_NETWKSTAGETINFO		63
#define LANMAN_DOSPRINTQENUM		69
#define LANMAN_DOSPRINTQGETINFO		70
#define LANMAN_WPRINTQUEUEPAUSE		74
#define LANMAN_WPRINTQUEUERESUME	75
#define LANMAN_WPRINTJOBENUMERATE	76
#define LANMAN_WPRINTJOBGETINFO		77
#define LANMAN_RDOSPRINTJOBDEL		81
#define LANMAN_RDOSPRINTJOBPAUSE	82
#define LANMAN_RDOSPRINTJOBRESUME	83
#define LANMAN_WPRINTDESTENUM		84
#define LANMAN_WPRINTDESTGETINFO	85
#define LANMAN_NETREMOTETOD		91
#define LANMAN_WPRINTQUEUEPURGE		103
#define LANMAN_NETSERVERENUM2		104
#define LANMAN_WACCESSGETUSERPERMS	105
#define LANMAN_SETUSERPASSWORD		115
#define LANMAN_NETWKSTAUSERLOGON	132
#define LANMAN_NETWKSTAUSERLOGOFF	133
#define LANMAN_PRINTJOBINFO		147
#define LANMAN_WPRINTDRIVERENUM		205
#define LANMAN_WPRINTQPROCENUM		206
#define LANMAN_WPRINTPORTENUM		207
#define LANMAN_SAMOEMCHANGEPASSWORD	214

static const value_string commands[] = {
	{LANMAN_NETSHAREENUM,		"NetShareEnum"},
	{LANMAN_NETSHAREGETINFO,	"NetShareGetInfo"},
	{LANMAN_NETSERVERGETINFO,	"NetServerGetInfo"},
	{LANMAN_NETGROUPGETUSERS,	"NetGroupGetUsers"},
	{LANMAN_NETUSERGETINFO,		"NetUserGetInfo"},
	{LANMAN_NETUSERGETGROUPS,	"NetUserGetGroups"},
	{LANMAN_NETWKSTAGETINFO,	"NetWkstaGetInfo"},
	{LANMAN_DOSPRINTQENUM,		"DOSPrintQEnum"},
	{LANMAN_DOSPRINTQGETINFO,	"DOSPrintQGetInfo"},
	{LANMAN_WPRINTQUEUEPAUSE,	"WPrintQueuePause"},
	{LANMAN_WPRINTQUEUERESUME,	"WPrintQueueResume"},
	{LANMAN_WPRINTJOBENUMERATE,	"WPrintJobEnumerate"},
	{LANMAN_WPRINTJOBGETINFO,	"WPrintJobGetInfo"},
	{LANMAN_RDOSPRINTJOBDEL,	"RDOSPrintJobDel"},
	{LANMAN_RDOSPRINTJOBPAUSE,	"RDOSPrintJobPause"},
	{LANMAN_RDOSPRINTJOBRESUME,	"RDOSPrintJobResume"},
	{LANMAN_WPRINTDESTENUM,		"WPrintDestEnum"},
	{LANMAN_WPRINTDESTGETINFO,	"WPrintDestGetInfo"},
	{LANMAN_NETREMOTETOD,		"NetRemoteTOD"},
	{LANMAN_WPRINTQUEUEPURGE,	"WPrintQueuePurge"},
	{LANMAN_NETSERVERENUM2,		"NetServerEnum2"},
	{LANMAN_WACCESSGETUSERPERMS,	"WAccessGetUserPerms"},
	{LANMAN_SETUSERPASSWORD,	"SetUserPassword"},
	{LANMAN_NETWKSTAUSERLOGON,	"NetWkstaUserLogon"},
	{LANMAN_NETWKSTAUSERLOGOFF,	"NetWkstaUserLogoff"},
	{LANMAN_PRINTJOBINFO,		"PrintJobInfo"},
	{LANMAN_WPRINTDRIVERENUM,	"WPrintDriverEnum"},
	{LANMAN_WPRINTQPROCENUM,	"WPrintQProcEnum"},
	{LANMAN_WPRINTPORTENUM,		"WPrintPortEnum"},
	{LANMAN_SAMOEMCHANGEPASSWORD,	"SamOEMChangePassword"},
	{0,	NULL}
};

struct lanman_dissector {
	int	command;
	int	(*request)(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
			   struct smb_request_val *request_val,
			   int offset);
	int	(*response)(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
			    struct smb_request_val *request_val,
			    int offset, guint16 status, int convert);
};

struct lanman_dissector lmd[] = {
	{ LANMAN_NETSHAREENUM,
	  netshareenum_request,
	  netshareenum_response },

	{ LANMAN_NETSHAREGETINFO,
	  netsharegetinfo_request,
	  netsharegetinfo_response },

	{ LANMAN_NETSERVERGETINFO,
	  netservergetinfo_request,
	  netservergetinfo_response },

	{ LANMAN_NETUSERGETINFO,
	  netusergetinfo_request,
	  netusergetinfo_response },

	{ LANMAN_NETREMOTETOD,
	  netremotetod_request,
	  netremotetod_response },

	{ LANMAN_NETSERVERENUM2,
	  netserverenum2_request,
	  netserverenum2_response },

	{ LANMAN_NETWKSTAGETINFO,
	  netwkstagetinfo_request,
	  netwkstagetinfo_response },

	{ LANMAN_NETWKSTAUSERLOGON,
	  netwkstauserlogon_request,
	  netwkstauserlogon_response },

	{ LANMAN_NETWKSTAUSERLOGOFF,
	  netwkstauserlogoff_request,
	  netwkstauserlogoff_response },

	{ LANMAN_SAMOEMCHANGEPASSWORD,
	  samoemchangepassword_request,
	  samoemchangepassword_response },

	{ -1, NULL, NULL }
};

struct lanman_dissector *find_lanman_dissector(int cmd)
{
	int i;

	for (i = 0; lmd[i].command != -1; i++) {
		if (lmd[i].command == cmd)
			return &lmd[i];
	}
	return NULL;
}

static gboolean
dissect_pipe_lanman(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	struct smb_info *smb_info = pinfo->private;
	struct smb_request_val *request_val = smb_info->request_val;
	int offset = 0;
	guint16 cmd;
	guint16 status;
	int convert;
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	struct lanman_dissector *dis;
	guint param_descriptor_len, return_descriptor_len;

	if (check_col(pinfo->fd, COL_PROTOCOL)) {
		col_set_str(pinfo->fd, COL_PROTOCOL, "LANMAN");
	}

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, proto_smb_lanman,
			tvb, 0, tvb_length(tvb), FALSE);
		tree = proto_item_add_subtree(item, ett_lanman);
	}

	/*
	 * Don't try to decode continuation messages.
	 *
	 * XXX - at some point, we will probably be handed tvbuffs
	 * for the parameters of the first message and for the
	 * reassembled contents of the data of the first message
	 * and all the continuations, and should dissect it.
	 *
	 * Transaction reassembly may, however, be an option, so that if
	 * we don't *have* all the reply messages, you at least can
	 * see what you have, by turning the option off.  (We don't know
	 * that we don't have them until we get to the end of the capture,
	 * but, by that time, it may be too late to dissect what we have;
	 * in Tethereal, for example, there's no going back....)
	 */
	if (smb_info->ddisp) {
		if (check_col(pinfo->fd, COL_INFO)) {
			col_set_str(pinfo->fd, COL_INFO, "Transact Continuation");
		}
		if (smb_info->continuation_val != NULL) {
			/* continuation from the message in frame xx */
			proto_tree_add_uint(tree, hf_continuation_from, tvb,
			    0, 0, smb_info->continuation_val->frame);
		}
		proto_tree_add_text(tree, tvb, 0, tvb_length(tvb),
		    "Continuation data");
		return TRUE;
	}

	if (smb_info->request) { /* this is a request */
		/* function code */
		cmd = tvb_get_letohs(tvb, offset);
		if (check_col(pinfo->fd, COL_INFO)) {
			col_add_fstr(pinfo->fd, COL_INFO, "%s Request", val_to_str(cmd, commands, "Unknown Command:0x%02x"));
		}
		proto_tree_add_uint(tree, hf_function_code, tvb, offset, 2,
		    cmd);
		offset += 2;

		/*
		 * If we haven't already done so, save the function code in
		 * the structure we were handed, so that it's available to
		 * the code parsing the reply.
		 */
		if (!pinfo->fd->flags.visited)
			request_val->last_lanman_cmd = cmd;

		/* parameter descriptor */
		param_descriptor_len = tvb_strsize(tvb, offset);
		proto_tree_add_item(tree, hf_param_desc, tvb, offset,
		    param_descriptor_len, TRUE);
		if (!pinfo->fd->flags.visited) {
			/*
			 * Save the parameter descriptor for future use.
			 */
			g_assert(request_val->last_param_descrip == NULL);
			request_val->last_param_descrip =
			    g_malloc(param_descriptor_len);
			strcpy(request_val->last_param_descrip,
			    tvb_get_ptr(tvb, offset, param_descriptor_len));
		}
		offset += param_descriptor_len;

		/* return descriptor */
		return_descriptor_len = tvb_strsize(tvb, offset);
		proto_tree_add_item(tree, hf_return_desc, tvb, offset,
		    return_descriptor_len, TRUE);
		if (!pinfo->fd->flags.visited) {
			/*
			 * Save the return descriptor for future use.
			 */
			g_assert(request_val->last_data_descrip == NULL);
			request_val->last_data_descrip =
			    g_malloc(return_descriptor_len);
			strcpy(request_val->last_data_descrip,
			    tvb_get_ptr(tvb, offset, return_descriptor_len));
		}
		offset += return_descriptor_len;

		/* command parameters */
 		dis = find_lanman_dissector(cmd);
 		if (dis == NULL) {
 			offset = not_implemented(tvb, pinfo, tree, offset);
 			return FALSE;
 		}
		offset = (*(dis->request))(tvb, pinfo, tree, request_val,
		    offset);
	} else {
		/*
		 * This is a response.
		 * Have we seen the request to which it's a response?
		 */
		if (request_val == NULL)
			return FALSE;	/* no - can't dissect it */

		/* ok we have seen this one before */

		/* response to the request in frame xx */
		proto_tree_add_uint(tree, hf_response_to, tvb, 0, 0,
				    request_val->frame);
		/* command */
		if (check_col(pinfo->fd, COL_INFO)) {
			col_add_fstr(pinfo->fd, COL_INFO, "%s %sResponse",
			    val_to_str(request_val->last_lanman_cmd, commands, "Unknown Command (0x%02x)"),
			    smb_info->is_interim_response ? "Interim " : "");
		}
		proto_tree_add_uint(tree, hf_function_code, tvb, 0, 0,
		    request_val->last_lanman_cmd);

		if (smb_info->is_interim_response)
			return TRUE;	/* no data to dissect */

		/* command parameters */

		/* status */
		status = tvb_get_letohs(tvb, offset);
		proto_tree_add_uint(tree, hf_status, tvb, offset, 2, status);
		offset += 2;

		/* convert */
		convert = tvb_get_letohs(tvb, offset);
		proto_tree_add_uint(tree, hf_convert, tvb, offset, 2, convert);
		offset += 2;

		/*
		 * "convert" is relative to the beginning of the data
		 * area, but we're handed a tvbuff that starts at the
		 * beginning of the parameter area, so we need to
		 * add "smb_info->data_offset" to offsets after
		 * subtracting "convert"; subtract it from "convert"
		 * so that it gets added in for free.
		 */
		convert -= smb_info->data_offset;

		dis = find_lanman_dissector(request_val->last_lanman_cmd);
 		if (dis == NULL) {
 			offset = not_implemented(tvb, pinfo, tree, offset);
 			return FALSE;
 		}
		offset = (*(dis->response))(tvb, pinfo, tree, request_val,
		    offset, status, convert);
	}

	return TRUE;
}



gboolean
dissect_pipe_smb(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	struct smb_info *smb_info = pinfo->private;

	if (!proto_is_protocol_enabled(proto_smb_lanman))
		return FALSE;
	pinfo->current_proto = "LANMAN";

	if (smb_info->trans_cmd && strcmp(smb_info->trans_cmd, "LANMAN") == 0) {
		/* Try to decode a LANMAN */

		return dissect_pipe_lanman(tvb, pinfo, tree);
	}

	return FALSE;
}

void
register_proto_smb_pipe(void)
{
	static hf_register_info hf[] = {
		{ &hf_function_code,
			{ "Function Code", "lanman.function_code", FT_UINT16, BASE_DEC,
			VALS(commands), 0, "LANMAN Function Code/Command", HFILL }},

		{ &hf_param_desc,
			{ "Parameter Descriptor", "lanman.param_desc", FT_STRING, BASE_NONE,
			NULL, 0, "LANMAN Parameter Descriptor", HFILL }},

		{ &hf_return_desc,
			{ "Return Descriptor", "lanman.ret_desc", FT_STRING, BASE_NONE,
			NULL, 0, "LANMAN Return Descriptor", HFILL }},

		{ &hf_not_implemented,
			{ "Unknown Data", "lanman.not_implemented", FT_BYTES, BASE_HEX,
			NULL, 0, "Decoding of this data is not implemented yet", HFILL }},

		{ &hf_detail_level,
			{ "Detail Level", "lanman.level", FT_UINT16, BASE_DEC,
			NULL, 0, "LANMAN Detail Level", HFILL }},

		{ &hf_recv_buf_len,
			{ "Receive Buffer Length", "lanman.recv_buf_len", FT_UINT16, BASE_DEC,
			NULL, 0, "LANMAN Receive Buffer Length", HFILL }},

		{ &hf_response_to,
			{ "Response to request in frame", "lanman.response_to", FT_UINT32, BASE_DEC,
			NULL, 0, "This is a LANMAN response to the request in the frame in question", HFILL }},

		{ &hf_continuation_from,
			{ "Continuation from message in frame", "lanman.continuation_from", FT_UINT32, BASE_DEC,
			NULL, 0, "This is a LANMAN continuation from the message in the frame in question", HFILL }},

		{ &hf_status,
			{ "Status", "lanman.status", FT_UINT16, BASE_DEC,
			VALS(status_vals), 0, "LANMAN Return status", HFILL }},

		{ &hf_convert,
			{ "Convert", "lanman.convert", FT_UINT16, BASE_DEC,
			NULL, 0, "LANMAN Convert", HFILL }},

		{ &hf_ecount,
			{ "Entry Count", "lanman.entry_count", FT_UINT16, BASE_DEC,
			NULL, 0, "LANMAN Number of Entries", HFILL }},

		{ &hf_acount,
			{ "Available Entries", "lanman.available_count", FT_UINT16, BASE_DEC,
			NULL, 0, "LANMAN Number of Available Entries", HFILL }},

		{ &hf_share_name,
			{ "Share Name", "lanman.share.name", FT_STRING, BASE_NONE,
			NULL, 0, "LANMAN Name of Share", HFILL }},

		{ &hf_share_type,
			{ "Share Type", "lanman.share.type", FT_UINT16, BASE_DEC,
			VALS(share_type_vals), 0, "LANMAN Type of Share", HFILL }},

		{ &hf_share_comment,
			{ "Share Comment", "lanman.share.comment", FT_STRING, BASE_NONE,
			NULL, 0, "LANMAN Share Comment", HFILL }},

		{ &hf_share_permissions,
			{ "Share Permissions", "lanman.share.permissions", FT_UINT16, BASE_DEC,
			NULL, 0, "LANMAN Permissions on share", HFILL }},

		{ &hf_share_max_uses,
			{ "Share Max Uses", "lanman.share.max_uses", FT_UINT16, BASE_DEC,
			NULL, 0, "LANMAN Max connections allowed to share", HFILL }},

		{ &hf_share_current_uses,
			{ "Share Current Uses", "lanman.share.current_uses", FT_UINT16, BASE_DEC,
			NULL, 0, "LANMAN Current connections to share", HFILL }},

		{ &hf_server_name,
			{ "Server Name", "lanman.server.name", FT_STRING, BASE_NONE,
			NULL, 0, "LANMAN Name of Server", HFILL }},

		{ &hf_server_major,
			{ "Major Version", "lanman.server.major", FT_UINT8, BASE_DEC,
			NULL, 0, "LANMAN Server Major Version", HFILL }},

		{ &hf_server_minor,
			{ "Minor Version", "lanman.server.minor", FT_UINT8, BASE_DEC,
			NULL, 0, "LANMAN Server Minor Version", HFILL }},

		{ &hf_server_comment,
			{ "Server Comment", "lanman.server.comment", FT_STRING, BASE_NONE,
			NULL, 0, "LANMAN Server Comment", HFILL }},

		{ &hf_abytes,
			{ "Available Bytes", "lanman.available_bytes", FT_UINT16, BASE_DEC,
			NULL, 0, "LANMAN Number of Available Bytes", HFILL }},

		{ &hf_current_time,
			{ "Current Date/Time", "lanman.current_time", FT_ABSOLUTE_TIME, BASE_NONE,
			NULL, 0, "LANMAN Current date and time, in seconds since 00:00:00, January 1, 1970", HFILL }},

		{ &hf_msecs,
			{ "Milliseconds", "lanman.msecs", FT_UINT32, BASE_DEC,
			NULL, 0, "LANMAN Milliseconds since arbitrary time in the past (typically boot time)", HFILL }},

		{ &hf_hour,
			{ "Hour", "lanman.hour", FT_UINT8, BASE_DEC,
			NULL, 0, "LANMAN Current hour", HFILL }},

		{ &hf_minute,
			{ "Minute", "lanman.minute", FT_UINT8, BASE_DEC,
			NULL, 0, "LANMAN Current minute", HFILL }},

		{ &hf_second,
			{ "Second", "lanman.second", FT_UINT8, BASE_DEC,
			NULL, 0, "LANMAN Current second", HFILL }},

		{ &hf_hundredths,
			{ "Hundredths of a second", "lanman.hundredths", FT_UINT8, BASE_DEC,
			NULL, 0, "LANMAN Current hundredths of a second", HFILL }},

		{ &hf_tzoffset,
			{ "Time Zone Offset", "lanman.tzoffset", FT_INT16, BASE_DEC,
			NULL, 0, "LANMAN Offset of time zone from GMT, in minutes", HFILL }},

		{ &hf_timeinterval,
			{ "Time Interval", "lanman.timeinterval", FT_UINT16, BASE_DEC,
			NULL, 0, "LANMAN .0001 second units per clock tick", HFILL }},

		{ &hf_day,
			{ "Day", "lanman.day", FT_UINT8, BASE_DEC,
			NULL, 0, "LANMAN Current day", HFILL }},

		{ &hf_month,
			{ "Month", "lanman.month", FT_UINT8, BASE_DEC,
			NULL, 0, "LANMAN Current month", HFILL }},

		{ &hf_year,
			{ "Year", "lanman.year", FT_UINT16, BASE_DEC,
			NULL, 0, "LANMAN Current year", HFILL }},

		{ &hf_weekday,
			{ "Weekday", "lanman.weekday", FT_UINT8, BASE_DEC,
			VALS(weekday_vals), 0, "LANMAN Current day of the week", HFILL }},

		{ &hf_computer_name,
			{ "Computer Name", "lanman.computer_name", FT_STRING, BASE_NONE,
			NULL, 0, "LANMAN Computer Name", HFILL }},

		{ &hf_user_name,
			{ "User Name", "lanman.user_name", FT_STRING, BASE_NONE,
			NULL, 0, "LANMAN User Name", HFILL }},

		{ &hf_workstation_domain,
			{ "Workstation Domain", "lanman.workstation_domain", FT_STRING, BASE_NONE,
			NULL, 0, "LANMAN Workstation Domain", HFILL }},

		{ &hf_workstation_major,
			{ "Workstation Major Version", "lanman.workstation_major", FT_UINT8, BASE_DEC,
			NULL, 0, "LANMAN Workstation Major Version", HFILL }},

		{ &hf_workstation_minor,
			{ "Workstation Minor Version", "lanman.workstation_minor", FT_UINT8, BASE_DEC,
			NULL, 0, "LANMAN Workstation Minor Version", HFILL }},

		{ &hf_logon_domain,
			{ "Logon Domain", "lanman.logon_domain", FT_STRING, BASE_NONE,
			NULL, 0, "LANMAN Logon Domain", HFILL }},

		{ &hf_other_domains,
			{ "Other Domains", "lanman.other_domains", FT_STRING, BASE_NONE,
			NULL, 0, "LANMAN Other Domains", HFILL }},

		{ &hf_password,
			{ "Password", "lanman.password", FT_STRING, BASE_NONE,
			NULL, 0, "LANMAN Password", HFILL }},

		{ &hf_workstation_name,
			{ "Workstation Name", "lanman.workstation_name", FT_STRING, BASE_NONE,
			NULL, 0, "LANMAN Workstation Name", HFILL }},

		{ &hf_ustruct_size,
			{ "Length of UStruct", "lanman.ustruct_size", FT_UINT16, BASE_DEC,
			NULL, 0, "LANMAN UStruct Length", HFILL }},

		{ &hf_logon_code,
			{ "Logon Code", "lanman.logon_code", FT_UINT16, BASE_DEC,
			VALS(status_vals), 0, "LANMAN Logon Code", HFILL }},

		{ &hf_privilege_level,
			{ "Privilege Level", "lanman.privilege_level", FT_UINT16, BASE_DEC,
			VALS(privilege_vals), 0, "LANMAN Privilege Level", HFILL }},

		{ &hf_operator_privileges,
			{ "Operator Privileges", "lanman.operator_privileges", FT_UINT32, BASE_DEC,
			VALS(op_privilege_vals), 0, "LANMAN Operator Privileges", HFILL }},

		{ &hf_num_logons,
			{ "Number of Logons", "lanman.num_logons", FT_UINT16, BASE_DEC,
			NULL, 0, "LANMAN Number of Logons", HFILL }},

		{ &hf_bad_pw_count,
			{ "Bad Password Count", "lanman.bad_pw_count", FT_UINT16, BASE_DEC,
			NULL, 0, "LANMAN Number of incorrect passwords entered since last successful login", HFILL }},

		{ &hf_last_logon,
			{ "Last Logon Date/Time", "lanman.last_logon", FT_ABSOLUTE_TIME, BASE_NONE,
			NULL, 0, "LANMAN Date and time of last logon", HFILL }},

		{ &hf_last_logoff,
			{ "Last Logoff Date/Time", "lanman.last_logoff", FT_ABSOLUTE_TIME, BASE_NONE,
			NULL, 0, "LANMAN Date and time of last logoff", HFILL }},

		{ &hf_logoff_time,
			{ "Logoff Date/Time", "lanman.logoff_time", FT_ABSOLUTE_TIME, BASE_NONE,
			NULL, 0, "LANMAN Date and time when user should log off", HFILL }},

		{ &hf_kickoff_time,
			{ "Kickoff Date/Time", "lanman.kickoff_time", FT_ABSOLUTE_TIME, BASE_NONE,
			NULL, 0, "LANMAN Date and time when user will be logged off", HFILL }},

		{ &hf_password_age,
			{ "Password Age", "lanman.password_age", FT_RELATIVE_TIME, BASE_NONE,
			NULL, 0, "LANMAN Time since user last changed his/her password", HFILL }},

		{ &hf_password_can_change,
			{ "Password Can Change", "lanman.password_can_change", FT_ABSOLUTE_TIME, BASE_NONE,
			NULL, 0, "LANMAN Date and time when user can change their password", HFILL }},

		{ &hf_password_must_change,
			{ "Password Must Change", "lanman.password_must_change", FT_ABSOLUTE_TIME, BASE_NONE,
			NULL, 0, "LANMAN Date and time when user must change their password", HFILL }},

		{ &hf_script_path,
			{ "Script Path", "lanman.script_path", FT_STRING, BASE_NONE,
			NULL, 0, "LANMAN Pathname of user's logon script", HFILL }},

		{ &hf_logoff_code,
			{ "Logoff Code", "lanman.logoff_code", FT_UINT16, BASE_DEC,
			VALS(status_vals), 0, "LANMAN Logoff Code", HFILL }},

		{ &hf_duration,
			{ "Duration of Session", "lanman.duration", FT_RELATIVE_TIME, BASE_NONE,
			NULL, 0, "LANMAN Number of seconds the user was logged on", HFILL }},

		{ &hf_user_comment,
			{ "User Comment", "lanman.user_comment", FT_STRING, BASE_NONE,
			NULL, 0, "LANMAN User Comment", HFILL }},

		{ &hf_full_name,
			{ "Full Name", "lanman.full_name", FT_STRING, BASE_NONE,
			NULL, 0, "LANMAN Full Name", HFILL }},

		{ &hf_homedir,
			{ "Home Directory", "lanman.homedir", FT_STRING, BASE_NONE,
			NULL, 0, "LANMAN Home Directory", HFILL }},

		{ &hf_parameters,
			{ "Parameters", "lanman.parameters", FT_STRING, BASE_NONE,
			NULL, 0, "LANMAN Parameters", HFILL }},

		{ &hf_logon_server,
			{ "Logon Server", "lanman.logon_server", FT_STRING, BASE_NONE,
			NULL, 0, "LANMAN Logon Server", HFILL }},

		{ &hf_country_code,
			{ "Country Code", "lanman.country_code", FT_UINT16, BASE_DEC,
			NULL, 0, "LANMAN Country Code", HFILL }},

		{ &hf_workstations,
			{ "Workstations", "lanman.workstations", FT_STRING, BASE_NONE,
			NULL, 0, "LANMAN Workstations", HFILL }},

		{ &hf_max_storage,
			{ "Max Storage", "lanman.max_storage", FT_UINT32, BASE_DEC,
			NULL, 0, "LANMAN Max Storage", HFILL }},

		{ &hf_units_per_week,
			{ "Units Per Week", "lanman.units_per_week", FT_UINT16, BASE_DEC,
			NULL, 0, "LANMAN Units Per Week", HFILL }},

		{ &hf_logon_hours,
			{ "Logon Hours", "lanman.logon_hours", FT_BYTES, BASE_NONE,
			NULL, 0, "LANMAN Logon Hours", HFILL }},

		{ &hf_code_page,
			{ "Code Page", "lanman.code_page", FT_UINT16, BASE_DEC,
			NULL, 0, "LANMAN Code Page", HFILL }},

		{ &hf_new_password,
			{ "New Password", "lanman.new_password", FT_BYTES, BASE_HEX,
			NULL, 0, "LANMAN New Password (encrypted)", HFILL }},

		{ &hf_old_password,
			{ "Old Password", "lanman.old_password", FT_BYTES, BASE_HEX,
			NULL, 0, "LANMAN Old Password (encrypted)", HFILL }},

	};

	static gint *ett[] = {

		&ett_lanman,
		&ett_lanman_servers,
		&ett_lanman_server,
		&ett_lanman_shares,
		&ett_lanman_share,
	};


    	proto_smb_lanman = proto_register_protocol(
    		"Microsoft Windows Lanman Remote API Protocol", "LANMAN", "lanman");

	proto_register_field_array(proto_smb_lanman, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}
