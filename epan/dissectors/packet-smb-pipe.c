/*
XXX  Fixme : shouldnt show [malformed frame] for long packets
*/

/* packet-smb-pipe.c
 * Routines for SMB named pipe packet dissection
 * Copyright 1999, Richard Sharpe <rsharpe@ns.aus.com>
 * significant rewrite to tvbuffify the dissector, Ronnie Sahlberg and
 * Guy Harris 2001
 *
 * $Id$
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

#include <time.h>
#include <string.h>
#include <glib.h>
#include <ctype.h>
#include <epan/packet.h>
#include <epan/emem.h>
#include <epan/dissectors/packet-smb.h>
#include "packet-smb-pipe.h"
#include "packet-smb-browse.h"
#include "packet-smb-common.h"
#include "packet-windows-common.h"
#include "packet-dcerpc.h"
#include <epan/reassemble.h>

static int proto_smb_pipe = -1;
static int hf_pipe_function = -1;
static int hf_pipe_priority = -1;
static int hf_pipe_peek_available = -1;
static int hf_pipe_peek_remaining = -1;
static int hf_pipe_peek_status = -1;
static int hf_pipe_getinfo_info_level = -1;
static int hf_pipe_getinfo_output_buffer_size = -1;
static int hf_pipe_getinfo_input_buffer_size = -1;
static int hf_pipe_getinfo_maximum_instances = -1;
static int hf_pipe_getinfo_current_instances = -1;
static int hf_pipe_getinfo_pipe_name_length = -1;
static int hf_pipe_getinfo_pipe_name = -1;
static int hf_pipe_write_raw_bytes_written = -1;
static int hf_pipe_fragments = -1;
static int hf_pipe_fragment = -1;
static int hf_pipe_fragment_overlap = -1;
static int hf_pipe_fragment_overlap_conflict = -1;
static int hf_pipe_fragment_multiple_tails = -1;
static int hf_pipe_fragment_too_long_fragment = -1;
static int hf_pipe_fragment_error = -1;
static int hf_pipe_reassembled_in = -1;

static gint ett_smb_pipe = -1;
static gint ett_smb_pipe_fragment = -1;
static gint ett_smb_pipe_fragments = -1;

static const fragment_items smb_pipe_frag_items = {
	&ett_smb_pipe_fragment,
	&ett_smb_pipe_fragments,
	&hf_pipe_fragments,
	&hf_pipe_fragment,
	&hf_pipe_fragment_overlap,
	&hf_pipe_fragment_overlap_conflict,
	&hf_pipe_fragment_multiple_tails,
	&hf_pipe_fragment_too_long_fragment,
	&hf_pipe_fragment_error,
	NULL,
	"fragments"
};

static int proto_smb_lanman = -1;
static int hf_function_code = -1;
static int hf_param_desc = -1;
static int hf_return_desc = -1;
static int hf_aux_data_desc = -1;
static int hf_detail_level = -1;
static int hf_recv_buf_len = -1;
static int hf_send_buf_len = -1;
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
static int hf_share_path = -1;
static int hf_share_password = -1;
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
static int hf_enumeration_domain = -1;
static int hf_last_entry = -1;
static int hf_computer_name = -1;
static int hf_user_name = -1;
static int hf_group_name = -1;
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
static int hf_comment = -1;
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
static int hf_reserved = -1;

static gint ett_lanman = -1;
static gint ett_lanman_unknown_entries = -1;
static gint ett_lanman_unknown_entry = -1;
static gint ett_lanman_shares = -1;
static gint ett_lanman_share = -1;
static gint ett_lanman_groups = -1;
static gint ett_lanman_servers = -1;
static gint ett_lanman_server = -1;

static dissector_handle_t data_handle;

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
	{2226,  "Operation not permitted on Backup Domain Controller"},
	{2240,  "The user is not allowed to logon from this computer"},
	{2241,  "The user is not allowed to logon at this time"},
	{2242,  "The user password has expired"},
	{2243,  "The password cannot be changed"},
	{2246,  "The password is too short"},
	{0,     NULL}
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
add_word_param(tvbuff_t *tvb, int offset, int count _U_,
    packet_info *pinfo _U_, proto_tree *tree, int convert _U_, int hf_index)
{
	guint16 WParam;

	if (hf_index != -1)
		proto_tree_add_item(tree, hf_index, tvb, offset, 2, TRUE);
	else {
		WParam = tvb_get_letohs(tvb, offset);
		proto_tree_add_text(tree, tvb, offset, 2,
		    "Word Param: %u (0x%04X)", WParam, WParam);
	}
	offset += 2;
	return offset;
}

static int
add_dword_param(tvbuff_t *tvb, int offset, int count _U_,
    packet_info *pinfo _U_, proto_tree *tree, int convert _U_, int hf_index)
{
	guint32 LParam;

	if (hf_index != -1)
		proto_tree_add_item(tree, hf_index, tvb, offset, 4, TRUE);
	else {
		LParam = tvb_get_letohl(tvb, offset);
		proto_tree_add_text(tree, tvb, offset, 4,
		    "Doubleword Param: %u (0x%08X)", LParam, LParam);
	}
	offset += 4;
	return offset;
}

static int
add_byte_param(tvbuff_t *tvb, int offset, int count, packet_info *pinfo _U_,
    proto_tree *tree, int convert _U_, int hf_index)
{
	guint8 BParam;
	header_field_info *hfinfo;

	if (hf_index != -1) {
		hfinfo = proto_registrar_get_nth(hf_index);
		if (hfinfo && count != 1 &&
				(hfinfo->type == FT_INT8 || hfinfo->type == FT_UINT8)
				&& count != 1) {
			THROW(ReportedBoundsError);
		}
		proto_tree_add_item(tree, hf_index, tvb, offset, count, TRUE);
	} else {
		if (count == 1) {
			BParam = tvb_get_guint8(tvb, offset);
			proto_tree_add_text(tree, tvb, offset, count,
			    "Byte Param: %u (0x%02X)",
			    BParam, BParam);
		} else {
			proto_tree_add_text(tree, tvb, offset, count,
			    "Byte Param: %s",
			    tvb_bytes_to_str(tvb, offset, count));
		}
	}
	offset += count;
	return offset;
}

static int
add_pad_param(tvbuff_t *tvb _U_, int offset, int count, packet_info *pinfo _U_,
    proto_tree *tree _U_, int convert _U_, int hf_index _U_)
{
	/*
	 * This is for parameters that have descriptor entries but that
	 * are, in practice, just padding.
	 */
	offset += count;
	return offset;
}

static void
add_null_pointer_param(tvbuff_t *tvb, int offset, int count _U_,
    packet_info *pinfo _U_, proto_tree *tree, int convert _U_, int hf_index)
{
	if (hf_index != -1) {
		proto_tree_add_text(tree, tvb, offset, 0,
		  "%s (Null pointer)",
		  proto_registrar_get_name(hf_index));
	} else {
		proto_tree_add_text(tree, tvb, offset, 0,
		    "String Param (Null pointer)");
	}
}

static int
add_string_param(tvbuff_t *tvb, int offset, int count _U_,
    packet_info *pinfo _U_, proto_tree *tree, int convert _U_, int hf_index)
{
	guint string_len;

	string_len = tvb_strsize(tvb, offset);
	if (hf_index != -1) {
		proto_tree_add_item(tree, hf_index, tvb, offset, string_len,
		    TRUE);
	} else {
		proto_tree_add_text(tree, tvb, offset, string_len,
		    "String Param: %s",
		    tvb_format_text(tvb, offset, string_len));
	}
	offset += string_len;
	return offset;
}

static const char *
get_stringz_pointer_value(tvbuff_t *tvb, int offset, int convert, int *cptrp,
    int *lenp)
{
	int cptr;
	gint string_len;

	/* pointer to string */
	cptr = (tvb_get_letohl(tvb, offset)&0xffff)-convert;
	*cptrp = cptr;

	/* string */
	if (tvb_offset_exists(tvb, cptr) &&
	    (string_len = tvb_strnlen(tvb, cptr, -1)) != -1) {
	    	string_len++;	/* include the terminating '\0' */
	    	*lenp = string_len;
	    	return tvb_format_text(tvb, cptr, string_len - 1);
	} else
		return NULL;
}

static int
add_stringz_pointer_param(tvbuff_t *tvb, int offset, int count _U_,
    packet_info *pinfo _U_, proto_tree *tree, int convert, int hf_index)
{
	int cptr;
	const char *string;
	gint string_len;

	string = get_stringz_pointer_value(tvb, offset, convert, &cptr,
	    &string_len);
	offset += 4;

	/* string */
	if (string != NULL) {
		if (hf_index != -1) {
			proto_tree_add_item(tree, hf_index, tvb, cptr,
			    string_len, TRUE);
		} else {
			proto_tree_add_text(tree, tvb, cptr, string_len,
			    "String Param: %s", string);
		}
	} else {
		if (hf_index != -1) {
			proto_tree_add_text(tree, tvb, 0, 0,
			    "%s: <String goes past end of frame>",
			    proto_registrar_get_name(hf_index));
		} else {
			proto_tree_add_text(tree, tvb, 0, 0,
			    "String Param: <String goes past end of frame>");
		}
	}

	return offset;
}

static int
add_bytes_pointer_param(tvbuff_t *tvb, int offset, int count,
    packet_info *pinfo _U_, proto_tree *tree, int convert, int hf_index)
{
	int cptr;

	/* pointer to byte array */
	cptr = (tvb_get_letohl(tvb, offset)&0xffff)-convert;
	offset += 4;

	/* bytes */
	if (tvb_bytes_exist(tvb, cptr, count)) {
		if (hf_index != -1) {
			proto_tree_add_item(tree, hf_index, tvb, cptr,
			    count, TRUE);
		} else {
			proto_tree_add_text(tree, tvb, cptr, count,
			    "Byte Param: %s",
			    tvb_bytes_to_str(tvb, cptr, count));
		}
	} else {
		if (hf_index != -1) {
			proto_tree_add_text(tree, tvb, 0, 0,
			    "%s: <Bytes go past end of frame>",
			    proto_registrar_get_name(hf_index));
		} else {
			proto_tree_add_text(tree, tvb, 0, 0,
			    "Byte Param: <Bytes goes past end of frame>");
		}
	}

	return offset;
}

static int
add_detail_level(tvbuff_t *tvb, int offset, int count _U_, packet_info *pinfo,
    proto_tree *tree, int convert _U_, int hf_index)
{
	struct smb_info *smb_info = pinfo->private_data;
	smb_transact_info_t *trp = NULL;
	guint16 level;

	if (smb_info->sip->extra_info_type == SMB_EI_TRI)
		trp = smb_info->sip->extra_info;
		
	level = tvb_get_letohs(tvb, offset);
	if (!pinfo->fd->flags.visited)
		if (trp)
			trp->info_level = level;	/* remember this for the response */

	proto_tree_add_uint(tree, hf_index, tvb, offset, 2, level);
	offset += 2;
	return offset;
}

static int
add_max_uses(tvbuff_t *tvb, int offset, int count _U_, packet_info *pinfo _U_,
    proto_tree *tree, int convert _U_, int hf_index)
{
	guint16 WParam;

	WParam = tvb_get_letohs(tvb, offset);
	if (WParam == 0xffff) {	/* -1 */
		proto_tree_add_uint_format(tree, hf_index, tvb,
		    offset, 2, WParam,
		    "%s: No limit",
		    proto_registrar_get_name(hf_index));
	} else {
		proto_tree_add_uint(tree, hf_index, tvb,
			    offset, 2, WParam);
	}
	offset += 2;
	return offset;
}

static int
add_server_type(tvbuff_t *tvb, int offset, int count _U_,
    packet_info *pinfo, proto_tree *tree, int convert _U_, int hf_index _U_)
{
	offset = dissect_smb_server_type_flags(
		tvb, offset, pinfo, tree, NULL, FALSE);
	return offset;
}

static int
add_server_type_info(tvbuff_t *tvb, int offset, int count _U_,
    packet_info *pinfo, proto_tree *tree, int convert _U_, int hf_index _U_)
{
	offset = dissect_smb_server_type_flags(
		tvb, offset, pinfo, tree, NULL, TRUE);
	return offset;
}

static int
add_reltime(tvbuff_t *tvb, int offset, int count _U_, packet_info *pinfo _U_,
    proto_tree *tree, int convert _U_, int hf_index)
{
	nstime_t nstime;

	nstime.secs = tvb_get_letohl(tvb, offset);
	nstime.nsecs = 0;
	proto_tree_add_time_format(tree, hf_index, tvb, offset, 4,
	    &nstime, "%s: %s", proto_registrar_get_name(hf_index),
	    time_secs_to_str(nstime.secs));
	offset += 4;
	return offset;
}

/*
 * Sigh.  These are for handling Microsoft's annoying almost-UNIX-time-but-
 * it's-local-time-not-UTC time.
 */
static int
add_abstime_common(tvbuff_t *tvb, int offset, proto_tree *tree, int hf_index,
    const char *absent_name)
{
	nstime_t nstime;
	struct tm *tmp;

	nstime.secs = tvb_get_letohl(tvb, offset);
	nstime.nsecs = 0;
	/*
	 * Sigh.  Sometimes it appears that -1 means "unknown", and
	 * sometimes it appears that 0 means "unknown", for the last
	 * logoff date/time.
	 */
	if (nstime.secs == -1 || nstime.secs == 0) {
		proto_tree_add_time_format(tree, hf_index, tvb, offset, 4,
		    &nstime, "%s: %s", proto_registrar_get_name(hf_index),
		    absent_name);
	} else {
		/*
		 * Run it through "gmtime()" to break it down, and then
		 * run it through "mktime()" to put it back together
		 * as UTC.
		 */
		tmp = gmtime(&nstime.secs);
		tmp->tm_isdst = -1;	/* we don't know if it's DST or not */
		nstime.secs = mktime(tmp);
		proto_tree_add_time(tree, hf_index, tvb, offset, 4,
		    &nstime);
	}
	offset += 4;
	return offset;
}

static int
add_abstime_absent_never(tvbuff_t *tvb, int offset, int count _U_,
    packet_info *pinfo _U_, proto_tree *tree, int convert _U_, int hf_index)
{
	return add_abstime_common(tvb, offset, tree, hf_index, "Never");
}

static int
add_abstime_absent_unknown(tvbuff_t *tvb, int offset, int count _U_,
    packet_info *pinfo _U_, proto_tree *tree, int convert _U_, int hf_index)
{
	return add_abstime_common(tvb, offset, tree, hf_index, "Unknown");
}

static int
add_nlogons(tvbuff_t *tvb, int offset, int count _U_, packet_info *pinfo _U_,
    proto_tree *tree, int convert _U_, int hf_index)
{
	guint16 nlogons;

	nlogons = tvb_get_letohs(tvb, offset);
	if (nlogons == 0xffff)	/* -1 */
		proto_tree_add_uint_format(tree, hf_index, tvb, offset, 2,
		    nlogons, "%s: Unknown",
		    proto_registrar_get_name(hf_index));
	else
		proto_tree_add_uint(tree, hf_index, tvb, offset, 2,
		    nlogons);
	offset += 2;
	return offset;
}

static int
add_max_storage(tvbuff_t *tvb, int offset, int count _U_,
    packet_info *pinfo _U_, proto_tree *tree, int convert _U_, int hf_index)
{
	guint32 max_storage;

	max_storage = tvb_get_letohl(tvb, offset);
	if (max_storage == 0xffffffff)
		proto_tree_add_uint_format(tree, hf_index, tvb, offset, 4,
		    max_storage, "%s: No limit",
		    proto_registrar_get_name(hf_index));
	else
		proto_tree_add_uint(tree, hf_index, tvb, offset, 4,
		    max_storage);
	offset += 4;
	return offset;
}

static int
add_logon_hours(tvbuff_t *tvb, int offset, int count, packet_info *pinfo _U_,
    proto_tree *tree, int convert, int hf_index)
{
	int cptr;

	/* pointer to byte array */
	cptr = (tvb_get_letohl(tvb, offset)&0xffff)-convert;
	offset += 4;

	/* bytes */
	if (tvb_bytes_exist(tvb, cptr, count)) {
		if (count == 21) {
			/*
			 * The logon hours should be exactly 21 bytes long.
			 *
			 * XXX - should actually carve up the bits;
			 * we need the units per week to do that, though.
			 */
			proto_tree_add_item(tree, hf_index, tvb, cptr, count,
			    TRUE);
		} else {
			proto_tree_add_bytes_format(tree, hf_index, tvb,
			    cptr, count, tvb_get_ptr(tvb, cptr, count),
			    "%s: %s (wrong length, should be 21, is %d",
			    proto_registrar_get_name(hf_index),
			    tvb_bytes_to_str(tvb, cptr, count), count);
		}
	} else {
		proto_tree_add_text(tree, tvb, 0, 0,
		    "%s: <Bytes go past end of frame>",
		    proto_registrar_get_name(hf_index));
	}

	return offset;
}

static int
add_tzoffset(tvbuff_t *tvb, int offset, int count _U_, packet_info *pinfo _U_,
    proto_tree *tree, int convert _U_, int hf_index)
{
	gint16 tzoffset;

	tzoffset = tvb_get_letohs(tvb, offset);
	if (tzoffset < 0) {
		proto_tree_add_int_format(tree, hf_tzoffset, tvb, offset, 2,
		    tzoffset, "%s: %s east of UTC",
		    proto_registrar_get_name(hf_index),
		    time_secs_to_str(-tzoffset*60));
	} else if (tzoffset > 0) {
		proto_tree_add_int_format(tree, hf_tzoffset, tvb, offset, 2,
		    tzoffset, "%s: %s west of UTC",
		    proto_registrar_get_name(hf_index),
		    time_secs_to_str(tzoffset*60));
	} else {
		proto_tree_add_int_format(tree, hf_tzoffset, tvb, offset, 2,
		    tzoffset, "%s: at UTC",
		    proto_registrar_get_name(hf_index));
	}
	offset += 2;
	return offset;
}

static int
add_timeinterval(tvbuff_t *tvb, int offset, int count _U_,
    packet_info *pinfo _U_, proto_tree *tree, int convert _U_, int hf_index)
{
	guint16 timeinterval;

	timeinterval = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint_format(tree, hf_timeinterval, tvb, offset, 2,
	   timeinterval, "%s: %f seconds", proto_registrar_get_name(hf_index),
	   timeinterval*.0001);
	offset += 2;
	return offset;
}

static int
add_logon_args(tvbuff_t *tvb, int offset, int count, packet_info *pinfo _U_,
    proto_tree *tree, int convert _U_, int hf_index _U_)
{
	if (count != 54) {
		proto_tree_add_text(tree, tvb, offset, count,
		   "Bogus NetWkstaUserLogon parameters: length is %d, should be 54",
		   count);
		offset += count;
		return offset;
	}

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
	return offset;
}

/*
 * The following data structure describes the Remote API requests we
 * understand.
 *
 * Simply fill in the number and parameter information.
 * Try to keep them in order.
 *
 * We will extend this data structure as we try to decode more.
 */

/*
 * This is a pointer to a function to process an item.
 */
typedef int	(*item_func)(tvbuff_t *, int, int, packet_info *, proto_tree *,
			     int, int);

/*
 * Type of an item; determines what parameter strings are valid for
 * the item.
 */
typedef enum {
	PARAM_NONE,	/* for the end-of-list stopper */
	PARAM_WORD,	/* 'W' or 'h' - 16-bit word */
	PARAM_DWORD,	/* 'D' or 'i' - 32-bit word */
	PARAM_BYTES,	/* 'B' or 'b' or 'g' or 'O' - one or more bytes */
	PARAM_STRINGZ	/* 'z' or 'O' - null-terminated string */
} param_type_t;

/*
 * This structure describes an item; "hf_index" points to the index
 * for the field corresponding to that item, "func" points to the
 * function to use to add that item to the tree, and "type" is the
 * type that the item is supposed to have.
 */
typedef struct {
	int		*hf_index;
	item_func	func;
	param_type_t	type;
} item_t;

/*
 * This structure describes a list of items; each list of items
 * has a corresponding detail level.
 */
typedef struct {
	int		level;
	const item_t	*item_list;
} item_list_t;

struct lanman_desc {
	int		lanman_num;
	const item_t	*req;
	proto_item	*(*req_data_item)(tvbuff_t *, packet_info *,
					  proto_tree *, int);
	gint		*ett_req_data;
	const item_t	*req_data;
	const item_t	*req_aux_data;
	const item_t	*resp;
	const gchar	*resp_data_entry_list_label;
	gint		*ett_data_entry_list;
	proto_item	*(*resp_data_element_item)(tvbuff_t *, proto_tree *,
						   int);
	gint		*ett_resp_data_element_item;
	const item_list_t *resp_data_list;
	const item_t	*resp_aux_data;
};

static int no_hf = -1;	/* for padding crap */

static const item_t lm_params_req_netshareenum[] = {
	{ &hf_detail_level, add_detail_level, PARAM_WORD },
	{ &hf_recv_buf_len, add_word_param, PARAM_WORD },
	{ NULL, NULL, PARAM_NONE }
};

static const item_t lm_params_resp_netshareenum[] = {
	{ &hf_acount, add_word_param, PARAM_WORD },
	{ NULL, NULL, PARAM_NONE }
};

/*
 * Create a subtree for a share.
 */
static proto_item *
netshareenum_share_entry(tvbuff_t *tvb, proto_tree *tree, int offset)
{
	if (tree) {
		return proto_tree_add_text(tree, tvb, offset, -1,
		    "Share %.13s", tvb_get_ptr(tvb, offset, 13));
	} else
		return NULL;
}

static const item_t lm_null[] = {
	{ NULL, NULL, PARAM_NONE }
};

static const item_list_t lm_null_list[] = {
	{ -1, lm_null }
};

static const item_t lm_data_resp_netshareenum_1[] = {
	{ &hf_share_name, add_byte_param, PARAM_BYTES },
	{ &no_hf, add_pad_param, PARAM_BYTES },
	{ &hf_share_type, add_word_param, PARAM_WORD },
	{ &hf_share_comment, add_stringz_pointer_param, PARAM_STRINGZ },
	{ NULL, NULL, PARAM_NONE }
};

static const item_list_t lm_data_resp_netshareenum[] = {
	{ 1, lm_data_resp_netshareenum_1 },
	{ -1, lm_null }
};

static const item_t lm_params_req_netsharegetinfo[] = {
	{ &hf_share_name, add_string_param, PARAM_STRINGZ },
	{ &hf_detail_level, add_detail_level, PARAM_WORD },
	{ NULL, NULL, PARAM_NONE }
};

static const item_t lm_params_resp_netsharegetinfo[] = {
	{ &hf_abytes, add_word_param, PARAM_WORD },
	{ NULL, NULL, PARAM_NONE }
};

static const item_t lm_data_resp_netsharegetinfo_0[] = {
	{ &hf_share_name, add_byte_param, PARAM_BYTES },
	{ NULL, NULL, PARAM_NONE }
};

static const item_t lm_data_resp_netsharegetinfo_1[] = {
	{ &hf_share_name, add_byte_param, PARAM_BYTES },
	{ &no_hf, add_pad_param, PARAM_BYTES },
	{ &hf_share_type, add_word_param, PARAM_WORD },
	{ &hf_share_comment, add_stringz_pointer_param, PARAM_STRINGZ },
	{ NULL, NULL, PARAM_NONE }
};

static const item_t lm_data_resp_netsharegetinfo_2[] = {
	{ &hf_share_name, add_byte_param, PARAM_BYTES },
	{ &no_hf, add_pad_param, PARAM_BYTES },
	{ &hf_share_type, add_word_param, PARAM_WORD },
	{ &hf_share_comment, add_stringz_pointer_param, PARAM_STRINGZ },
	{ &hf_share_permissions, add_word_param, PARAM_WORD }, /* XXX - do as bit fields */
	{ &hf_share_max_uses, add_max_uses, PARAM_WORD },
	{ &hf_share_current_uses, add_word_param, PARAM_WORD },
	{ &hf_share_path, add_stringz_pointer_param, PARAM_STRINGZ },
	{ &hf_share_password, add_byte_param, PARAM_BYTES },
	{ NULL, NULL, PARAM_NONE }
};

static const item_list_t lm_data_resp_netsharegetinfo[] = {
	{ 0, lm_data_resp_netsharegetinfo_0 },
	{ 1, lm_data_resp_netsharegetinfo_1 },
	{ 2, lm_data_resp_netsharegetinfo_2 },
	{ -1, lm_null }
};

static const item_t lm_params_req_netservergetinfo[] = {
	{ &hf_detail_level, add_detail_level, PARAM_WORD },
	{ NULL, NULL, PARAM_NONE }
};

static const item_t lm_params_resp_netservergetinfo[] = {
	{ &hf_abytes, add_word_param, PARAM_WORD },
	{ NULL, NULL, PARAM_NONE }
};

static const item_t lm_data_serverinfo_0[] = {
	{ &hf_server_name, add_byte_param, PARAM_BYTES },
	{ NULL, NULL, PARAM_NONE }
};

static const item_t lm_data_serverinfo_1[] = {
	{ &hf_server_name, add_byte_param, PARAM_BYTES },
	{ &hf_server_major, add_byte_param, PARAM_BYTES },
	{ &hf_server_minor, add_byte_param, PARAM_BYTES },
	{ &no_hf, add_server_type, PARAM_DWORD },
	{ &hf_server_comment, add_stringz_pointer_param, PARAM_STRINGZ },
	{ NULL, NULL, PARAM_NONE }
};

static const item_list_t lm_data_serverinfo[] = {
	{ 0, lm_data_serverinfo_0 },
	{ 1, lm_data_serverinfo_1 },
	{ -1, lm_null }
};

static const item_t lm_params_req_netusergetinfo[] = {
	{ &hf_user_name, add_string_param, PARAM_STRINGZ },
	{ &hf_detail_level, add_detail_level, PARAM_WORD },
	{ NULL, NULL, PARAM_NONE }
};

static const item_t lm_params_resp_netusergetinfo[] = {
	{ &hf_abytes, add_word_param, PARAM_WORD },
	{ NULL, NULL, PARAM_NONE }
};

static const item_t lm_data_resp_netusergetinfo_11[] = {
	{ &hf_user_name, add_byte_param, PARAM_BYTES },
	{ &no_hf, add_pad_param, PARAM_BYTES },
	{ &hf_comment, add_stringz_pointer_param, PARAM_STRINGZ },
	{ &hf_user_comment, add_stringz_pointer_param, PARAM_STRINGZ },
	{ &hf_full_name, add_stringz_pointer_param, PARAM_STRINGZ },
	{ &hf_privilege_level, add_word_param, PARAM_WORD },
	{ &hf_operator_privileges, add_dword_param, PARAM_DWORD },
	{ &hf_password_age, add_reltime, PARAM_DWORD },
	{ &hf_homedir, add_stringz_pointer_param, PARAM_STRINGZ },
	{ &hf_parameters, add_stringz_pointer_param, PARAM_STRINGZ },
	{ &hf_last_logon, add_abstime_absent_unknown, PARAM_DWORD },
	{ &hf_last_logoff, add_abstime_absent_unknown, PARAM_DWORD },
	{ &hf_bad_pw_count, add_word_param, PARAM_WORD },
	{ &hf_num_logons, add_nlogons, PARAM_WORD },
	{ &hf_logon_server, add_stringz_pointer_param, PARAM_STRINGZ },
	{ &hf_country_code, add_word_param, PARAM_WORD },
	{ &hf_workstations, add_stringz_pointer_param, PARAM_STRINGZ },
	{ &hf_max_storage, add_max_storage, PARAM_DWORD },
	{ &hf_units_per_week, add_word_param, PARAM_WORD },
	{ &hf_logon_hours, add_logon_hours, PARAM_BYTES },
	{ &hf_code_page, add_word_param, PARAM_WORD },
	{ NULL, NULL, PARAM_NONE }
};

static const item_list_t lm_data_resp_netusergetinfo[] = {
	{ 11, lm_data_resp_netusergetinfo_11 },
	{ -1, lm_null }
};

static const item_t lm_params_req_netusergetgroups[] = {
	{ &hf_user_name, add_string_param, PARAM_STRINGZ },
	{ &hf_detail_level, add_detail_level, PARAM_WORD },
	{ NULL, NULL, PARAM_NONE }
};

static const item_t lm_params_resp_netusergetgroups[] = {
	{ &hf_abytes, add_word_param, PARAM_WORD },
	{ NULL, NULL, PARAM_NONE }
};

static const item_t lm_data_resp_netusergetgroups_0[] = {
	{ &hf_group_name, add_byte_param, PARAM_BYTES },
	{ NULL, NULL, PARAM_NONE }
};

static const item_list_t lm_data_resp_netusergetgroups[] = {
	{ 0, lm_data_resp_netusergetgroups_0 },
	{ -1, lm_null }
};

/*
 * Has no detail level; make it the default.
 */
static const item_t lm_data_resp_netremotetod_nolevel[] = {
	{ &hf_current_time, add_abstime_absent_unknown, PARAM_DWORD },
	{ &hf_msecs, add_dword_param, PARAM_DWORD },
	{ &hf_hour, add_byte_param, PARAM_BYTES },
	{ &hf_minute, add_byte_param, PARAM_BYTES },
	{ &hf_second, add_byte_param, PARAM_BYTES },
	{ &hf_hundredths, add_byte_param, PARAM_BYTES },
	{ &hf_tzoffset, add_tzoffset, PARAM_WORD },
	{ &hf_timeinterval, add_timeinterval, PARAM_WORD },
	{ &hf_day, add_byte_param, PARAM_BYTES },
	{ &hf_month, add_byte_param, PARAM_BYTES },
	{ &hf_year, add_word_param, PARAM_WORD },
	{ &hf_weekday, add_byte_param, PARAM_BYTES },
	{ NULL, NULL, PARAM_NONE }
};

static const item_list_t lm_data_resp_netremotetod[] = {
	{ -1, lm_data_resp_netremotetod_nolevel },
};

static const item_t lm_params_req_netserverenum2[] = {
	{ &hf_detail_level, add_detail_level, PARAM_WORD },
	{ &no_hf, add_server_type_info, PARAM_DWORD },
	{ &hf_enumeration_domain, add_string_param, PARAM_STRINGZ },
	{ NULL, NULL, PARAM_NONE }
};

/*
 * Create a subtree for a server.
 */
static proto_item *
netserverenum2_server_entry(tvbuff_t *tvb, proto_tree *tree, int offset)
{
	if (tree) {
		return proto_tree_add_text(tree, tvb, offset, -1,
			    "Server %.16s", tvb_get_ptr(tvb, offset, 16));
	} else
		return NULL;
}

static const item_t lm_params_resp_netserverenum2[] = {
	{ &hf_acount, add_word_param, PARAM_WORD },
	{ NULL, NULL, PARAM_NONE }
};


static const item_t lm_params_req_netserverenum3[] = {
	{ &hf_detail_level, add_detail_level, PARAM_WORD },
	{ &no_hf, add_server_type_info, PARAM_DWORD },
	{ &hf_enumeration_domain, add_string_param, PARAM_STRINGZ },
	{ &hf_last_entry, add_string_param, PARAM_STRINGZ },
	{ NULL, NULL, PARAM_NONE }
};


static const item_t lm_params_req_netwkstagetinfo[] = {
	{ &hf_detail_level, add_detail_level, PARAM_WORD },
	{ NULL, NULL, PARAM_NONE }
};

static const item_t lm_params_resp_netwkstagetinfo[] = {
	{ &hf_abytes, add_word_param, PARAM_WORD },
	{ NULL, NULL, PARAM_NONE }
};

static const item_t lm_data_resp_netwkstagetinfo_10[] = {
	{ &hf_computer_name, add_stringz_pointer_param, PARAM_STRINGZ },
	{ &hf_user_name, add_stringz_pointer_param, PARAM_STRINGZ },
	{ &hf_workstation_domain, add_stringz_pointer_param, PARAM_STRINGZ },
	{ &hf_workstation_major, add_byte_param, PARAM_BYTES },
	{ &hf_workstation_minor, add_byte_param, PARAM_BYTES },
	{ &hf_logon_domain, add_stringz_pointer_param, PARAM_STRINGZ },
	{ &hf_other_domains, add_stringz_pointer_param, PARAM_STRINGZ },
	{ NULL, NULL, PARAM_NONE }
};

static const item_list_t lm_data_resp_netwkstagetinfo[] = {
	{ 10, lm_data_resp_netwkstagetinfo_10 },
	{ -1, lm_null }
};

static const item_t lm_params_req_netwkstauserlogon[] = {
	{ &no_hf, add_stringz_pointer_param, PARAM_STRINGZ },
	{ &no_hf, add_stringz_pointer_param, PARAM_STRINGZ },
	{ &hf_detail_level, add_detail_level, PARAM_WORD },
	{ &no_hf, add_logon_args, PARAM_BYTES },
	{ &hf_ustruct_size, add_word_param, PARAM_WORD },
	{ NULL, NULL, PARAM_NONE }
};

static const item_t lm_params_resp_netwkstauserlogon[] = {
	{ &hf_abytes, add_word_param, PARAM_WORD },
	{ NULL, NULL, PARAM_NONE }
};

static const item_t lm_data_resp_netwkstauserlogon_1[] = {
	{ &hf_logon_code, add_word_param, PARAM_WORD },
	{ &hf_user_name, add_byte_param, PARAM_BYTES },
	{ &no_hf, add_pad_param, PARAM_BYTES },
	{ &hf_privilege_level, add_word_param, PARAM_WORD },
	{ &hf_operator_privileges, add_dword_param, PARAM_DWORD },
	{ &hf_num_logons, add_nlogons, PARAM_WORD },
	{ &hf_bad_pw_count, add_word_param, PARAM_WORD },
	{ &hf_last_logon, add_abstime_absent_unknown, PARAM_DWORD },
	{ &hf_last_logoff, add_abstime_absent_unknown, PARAM_DWORD },
	{ &hf_logoff_time, add_abstime_absent_never, PARAM_DWORD },
	{ &hf_kickoff_time, add_abstime_absent_never, PARAM_DWORD },
	{ &hf_password_age, add_reltime, PARAM_DWORD },
	{ &hf_password_can_change, add_abstime_absent_never, PARAM_DWORD },
	{ &hf_password_must_change, add_abstime_absent_never, PARAM_DWORD },
	{ &hf_server_name, add_stringz_pointer_param, PARAM_STRINGZ },
	{ &hf_logon_domain, add_stringz_pointer_param, PARAM_STRINGZ },
	{ &hf_script_path, add_stringz_pointer_param, PARAM_STRINGZ },
	{ &hf_reserved, add_dword_param, PARAM_DWORD },
	{ NULL, NULL, PARAM_NONE }
};

static const item_list_t lm_data_resp_netwkstauserlogon[] = {
	{ 1, lm_data_resp_netwkstauserlogon_1 },
	{ -1, lm_null }
};

static const item_t lm_params_req_netwkstauserlogoff[] = {
	{ &hf_user_name, add_byte_param, PARAM_BYTES },
	{ &no_hf, add_pad_param, PARAM_BYTES },
	{ &hf_workstation_name, add_byte_param, PARAM_BYTES },
	{ NULL, NULL, PARAM_NONE }
};

static const item_t lm_params_resp_netwkstauserlogoff[] = {
	{ &hf_abytes, add_word_param, PARAM_WORD },
	{ NULL, NULL, PARAM_NONE }
};

static const item_t lm_data_resp_netwkstauserlogoff_1[] = {
	{ &hf_logoff_code, add_word_param, PARAM_WORD },
	{ &hf_duration, add_reltime, PARAM_DWORD },
	{ &hf_num_logons, add_nlogons, PARAM_WORD },
	{ NULL, NULL, PARAM_NONE }
};

static const item_list_t lm_data_resp_netwkstauserlogoff[] = {
	{ 1, lm_data_resp_netwkstauserlogoff_1 },
	{ -1, lm_null }
};

static const item_t lm_params_req_samoemchangepassword[] = {
	{ &hf_user_name, add_string_param, PARAM_STRINGZ },
	{ NULL, NULL, PARAM_NONE }
};

static const item_t lm_data_req_samoemchangepassword[] = {
	{ &hf_new_password, add_byte_param, PARAM_BYTES },
	{ &hf_old_password, add_byte_param, PARAM_BYTES },
	{ NULL, NULL, PARAM_NONE }
};

#define API_NetShareEnum		0
#define API_NetShareGetInfo		1
#define API_NetShareSetInfo		2
#define API_NetShareAdd			3
#define API_NetShareDel			4
#define API_NetShareCheck		5
#define API_NetSessionEnum		6
#define API_NetSessionGetInfo		7
#define API_NetSessionDel		8
#define API_WconnectionEnum		9
#define API_NetFileEnum			10
#define API_NetFileGetInfo		11
#define API_NetFileClose		12
#define API_NetServerGetInfo		13
#define API_NetServerSetInfo		14
#define API_NetServerDiskEnum		15
#define API_NetServerAdminCommand	16
#define API_NetAuditOpen		17
#define API_NetAuditClear		18
#define API_NetErrorLogOpen		19
#define API_NetErrorLogClear		20
#define API_NetCharDevEnum		21
#define API_NetCharDevGetInfo		22
#define API_NetCharDevControl		23
#define API_NetCharDevQEnum		24
#define API_NetCharDevQGetInfo		25
#define API_NetCharDevQSetInfo		26
#define API_NetCharDevQPurge		27
#define API_NetCharDevQPurgeSelf	28
#define API_NetMessageNameEnum		29
#define API_NetMessageNameGetInfo	30
#define API_NetMessageNameAdd		31
#define API_NetMessageNameDel		32
#define API_NetMessageNameFwd		33
#define API_NetMessageNameUnFwd		34
#define API_NetMessageBufferSend	35
#define API_NetMessageFileSend		36
#define API_NetMessageLogFileSet	37
#define API_NetMessageLogFileGet	38
#define API_NetServiceEnum		39
#define API_NetServiceInstall		40
#define API_NetServiceControl		41
#define API_NetAccessEnum		42
#define API_NetAccessGetInfo		43
#define API_NetAccessSetInfo		44
#define API_NetAccessAdd		45
#define API_NetAccessDel		46
#define API_NetGroupEnum		47
#define API_NetGroupAdd			48
#define API_NetGroupDel			49
#define API_NetGroupAddUser		50
#define API_NetGroupDelUser		51
#define API_NetGroupGetUsers		52
#define API_NetUserEnum			53
#define API_NetUserAdd			54
#define API_NetUserDel			55
#define API_NetUserGetInfo		56
#define API_NetUserSetInfo		57
#define API_NetUserPasswordSet		58
#define API_NetUserGetGroups		59
/*This line and number replaced a Dead Entry for 60 */
/*This line and number replaced a Dead Entry for 61 */
#define API_NetWkstaSetUID		62
#define API_NetWkstaGetInfo		63
#define API_NetWkstaSetInfo		64
#define API_NetUseEnum			65
#define API_NetUseAdd			66
#define API_NetUseDel			67
#define API_NetUseGetInfo		68
#define API_WPrintQEnum			69
#define API_WPrintQGetInfo		70
#define API_WPrintQSetInfo		71
#define API_WPrintQAdd			72
#define API_WPrintQDel			73
#define API_WPrintQPause		74
#define API_WPrintQContinue		75
#define API_WPrintJobEnum		76
#define API_WPrintJobGetInfo		77
#define API_WPrintJobSetInfo_OLD	78
/* This line and number replaced a Dead Entry for 79 */
/* This line and number replaced a Dead Entry for 80 */
#define API_WPrintJobDel		81
#define API_WPrintJobPause		82
#define API_WPrintJobContinue		83
#define API_WPrintDestEnum		84
#define API_WPrintDestGetInfo		85
#define API_WPrintDestControl		86
#define API_NetProfileSave		87
#define API_NetProfileLoad		88
#define API_NetStatisticsGet		89
#define API_NetStatisticsClear		90
#define API_NetRemoteTOD		91
#define API_WNetBiosEnum		92
#define API_WNetBiosGetInfo		93
#define API_NetServerEnum		94
#define API_I_NetServerEnum		95
#define API_NetServiceGetInfo		96
/* This line and number replaced a Dead Entry for 97 */
/* This line and number replaced a Dead Entry for 98 */
/* This line and number replaced a Dead Entry for 99 */
/* This line and number replaced a Dead Entry for 100 */
/* This line and number replaced a Dead Entry for 101 */
/* This line and number replaced a Dead Entry for 102 */
#define API_WPrintQPurge		103
#define API_NetServerEnum2		104
#define API_NetAccessGetUserPerms	105
#define API_NetGroupGetInfo		106
#define API_NetGroupSetInfo		107
#define API_NetGroupSetUsers		108
#define API_NetUserSetGroups		109
#define API_NetUserModalsGet		110
#define API_NetUserModalsSet		111
#define API_NetFileEnum2		112
#define API_NetUserAdd2			113
#define API_NetUserSetInfo2		114
#define API_NetUserPasswordSet2		115
#define API_I_NetServerEnum2		116
#define API_NetConfigGet2		117
#define API_NetConfigGetAll2		118
#define API_NetGetDCName		119
#define API_NetHandleGetInfo		120
#define API_NetHandleSetInfo		121
#define API_NetStatisticsGet2		122
#define API_WBuildGetInfo		123
#define API_NetFileGetInfo2		124
#define API_NetFileClose2		125
#define API_NetServerReqChallenge	126
#define API_NetServerAuthenticate	127
#define API_NetServerPasswordSet	128
#define API_WNetAccountDeltas		129
#define API_WNetAccountSync		130
#define API_NetUserEnum2		131
#define API_NetWkstaUserLogon		132
#define API_NetWkstaUserLogoff		133
#define API_NetLogonEnum		134
#define API_NetErrorLogRead		135
#define API_I_NetPathType		136
#define API_I_NetPathCanonicalize	137
#define API_I_NetPathCompare		138
#define API_I_NetNameValidate		139
#define API_I_NetNameCanonicalize	140
#define API_I_NetNameCompare		141
#define API_NetAuditRead		142
#define API_WPrintDestAdd		143
#define API_WPrintDestSetInfo		144
#define API_WPrintDestDel		145
#define API_NetUserValidate2		146
#define API_WPrintJobSetInfo		147
#define API_TI_NetServerDiskEnum	148
#define API_TI_NetServerDiskGetInfo	149
#define API_TI_FTVerifyMirror		150
#define API_TI_FTAbortVerify		151
#define API_TI_FTGetInfo		152
#define API_TI_FTSetInfo		153
#define API_TI_FTLockDisk		154
#define API_TI_FTFixError		155
#define API_TI_FTAbortFix		156
#define API_TI_FTDiagnoseError		157
#define API_TI_FTGetDriveStats		158
/* This line and number replaced a Dead Entry for 159 */
#define API_TI_FTErrorGetInfo		160
/* This line and number replaced a Dead Entry for 161 */
/* This line and number replaced a Dead Entry for 162 */
#define API_NetAccessCheck		163
#define API_NetAlertRaise		164
#define API_NetAlertStart		165
#define API_NetAlertStop		166
#define API_NetAuditWrite		167
#define API_NetIRemoteAPI		168
#define API_NetServiceStatus		169
#define API_I_NetServerRegister		170
#define API_I_NetServerDeregister	171
#define API_I_NetSessionEntryMake	172
#define API_I_NetSessionEntryClear	173
#define API_I_NetSessionEntryGetInfo	174
#define API_I_NetSessionEntrySetInfo	175
#define API_I_NetConnectionEntryMake	176
#define API_I_NetConnectionEntryClear	177
#define API_I_NetConnectionEntrySetInfo	178
#define API_I_NetConnectionEntryGetInfo	179
#define API_I_NetFileEntryMake		180
#define API_I_NetFileEntryClear		181
#define API_I_NetFileEntrySetInfo	182
#define API_I_NetFileEntryGetInfo	183
#define API_AltSrvMessageBufferSend	184
#define API_AltSrvMessageFileSend	185
#define API_wI_NetRplWkstaEnum		186
#define API_wI_NetRplWkstaGetInfo	187
#define API_wI_NetRplWkstaSetInfo	188
#define API_wI_NetRplWkstaAdd		189
#define API_wI_NetRplWkstaDel		190
#define API_wI_NetRplProfileEnum	191
#define API_wI_NetRplProfileGetInfo	192
#define API_wI_NetRplProfileSetInfo	193
#define API_wI_NetRplProfileAdd		194
#define API_wI_NetRplProfileDel		195
#define API_wI_NetRplProfileClone	196
#define API_wI_NetRplBaseProfileEnum	197
/* This line and number replaced a Dead Entry for 198 */
/* This line and number replaced a Dead Entry for 199 */
/* This line and number replaced a Dead Entry for 200 */
#define API_WIServerSetInfo		201
/* This line and number replaced a Dead Entry for 202 */
/* This line and number replaced a Dead Entry for 203 */
/* This line and number replaced a Dead Entry for 204 */
#define API_WPrintDriverEnum		205
#define API_WPrintQProcessorEnum	206
#define API_WPrintPortEnum		207
#define API_WNetWriteUpdateLog		208
#define API_WNetAccountUpdate		209
#define API_WNetAccountConfirmUpdate	210
#define API_NetConfigSet		211
#define API_WAccountsReplicate		212
/* 213 is used by WfW */
#define API_SamOEMChgPasswordUser2_P	214
#define API_NetServerEnum3		215
/* XXX - what about 216 through 249? */
#define API_WPrintDriverGetInfo		250
#define API_WPrintDriverSetInfo		251
#define API_NetAliasAdd			252
#define API_NetAliasDel			253
#define API_NetAliasGetInfo		254
#define API_NetAliasSetInfo		255
#define API_NetAliasEnum		256
#define API_NetUserGetLogonAsn		257
#define API_NetUserSetLogonAsn		258
#define API_NetUserGetAppSel		259
#define API_NetUserSetAppSel		260
#define API_NetAppAdd			261
#define API_NetAppDel			262
#define API_NetAppGetInfo		263
#define API_NetAppSetInfo		264
#define API_NetAppEnum			265
#define API_NetUserDCDBInit		266
#define API_NetDASDAdd			267
#define API_NetDASDDel			268
#define API_NetDASDGetInfo		269
#define API_NetDASDSetInfo		270
#define API_NetDASDEnum			271
#define API_NetDASDCheck		272
#define API_NetDASDCtl			273
#define API_NetUserRemoteLogonCheck	274
#define API_NetUserPasswordSet3		275
#define API_NetCreateRIPLMachine	276
#define API_NetDeleteRIPLMachine	277
#define API_NetGetRIPLMachineInfo	278
#define API_NetSetRIPLMachineInfo	279
#define API_NetEnumRIPLMachine		280
#define API_I_ShareAdd			281
#define API_I_AliasEnum			282
#define API_NetAccessApply		283
#define API_WPrt16Query			284
#define API_WPrt16Set			285
#define API_NetUserDel100		286
#define API_NetUserRemoteLogonCheck2	287
#define API_WRemoteTODSet		294
#define API_WPrintJobMoveAll		295
#define API_W16AppParmAdd		296
#define API_W16AppParmDel		297
#define API_W16AppParmGet		298
#define API_W16AppParmSet		299
#define API_W16RIPLMachineCreate	300
#define API_W16RIPLMachineGetInfo	301
#define API_W16RIPLMachineSetInfo	302
#define API_W16RIPLMachineEnum		303
#define API_W16RIPLMachineListParmEnum	304
#define API_W16RIPLMachClassGetInfo	305
#define API_W16RIPLMachClassEnum	306
#define API_W16RIPLMachClassCreate	307
#define API_W16RIPLMachClassSetInfo	308
#define API_W16RIPLMachClassDelete	309
#define API_W16RIPLMachClassLPEnum	310
#define API_W16RIPLMachineDelete	311
#define API_W16WSLevelGetInfo		312
#define API_NetServerNameAdd		313
#define API_NetServerNameDel		314
#define API_NetServerNameEnum		315
#define API_I_WDASDEnum			316
#define API_I_WDASDEnumTerminate	317
#define API_I_WDASDSetInfo2		318

static const struct lanman_desc lmd[] = {
	{ API_NetShareEnum,
	  lm_params_req_netshareenum,
	  NULL,
	  NULL,
	  lm_null,
	  lm_null,
	  lm_params_resp_netshareenum,
	  "Available Shares",
	  &ett_lanman_shares,
	  netshareenum_share_entry,
	  &ett_lanman_share,
	  lm_data_resp_netshareenum,
	  lm_null },

	{ API_NetShareGetInfo,
	  lm_params_req_netsharegetinfo,
	  NULL,
	  NULL,
	  lm_null,
	  lm_null,
	  lm_params_resp_netsharegetinfo,
	  NULL,
	  NULL,
	  NULL,
	  NULL,
	  lm_data_resp_netsharegetinfo,
	  lm_null },

	{ API_NetServerGetInfo,
	  lm_params_req_netservergetinfo,
	  NULL,
	  NULL,
	  lm_null,
	  lm_null,
	  lm_params_resp_netservergetinfo,
	  NULL,
	  NULL,
	  NULL,
	  NULL,
	  lm_data_serverinfo,
	  lm_null },

	{ API_NetUserGetInfo,
	  lm_params_req_netusergetinfo,
	  NULL,
	  NULL,
	  lm_null,
	  lm_null,
	  lm_params_resp_netusergetinfo,
	  NULL,
	  NULL,
	  NULL,
	  NULL,
	  lm_data_resp_netusergetinfo,
	  lm_null },

	{ API_NetUserGetGroups,
	  lm_params_req_netusergetgroups,
	  NULL,
	  NULL,
	  lm_null,
	  lm_null,
	  lm_params_resp_netusergetgroups,
	  "Groups",
	  &ett_lanman_groups,
	  NULL,
	  NULL,
	  lm_data_resp_netusergetgroups,
	  lm_null },

	{ API_NetRemoteTOD,
	  lm_null,
	  NULL,
	  NULL,
	  lm_null,
	  lm_null,
	  lm_null,
	  NULL,
	  NULL,
	  NULL,
	  NULL,
	  lm_data_resp_netremotetod,
	  lm_null },

	{ API_NetServerEnum2,
	  lm_params_req_netserverenum2,
	  NULL,
	  NULL,
	  lm_null,
	  lm_null,
	  lm_params_resp_netserverenum2,
	  "Servers",
	  &ett_lanman_servers,
	  netserverenum2_server_entry,
	  &ett_lanman_server,
	  lm_data_serverinfo,
	  lm_null },

	{ API_NetWkstaGetInfo,
	  lm_params_req_netwkstagetinfo,
	  NULL,
	  NULL,
	  lm_null,
	  lm_null,
	  lm_params_resp_netwkstagetinfo,
	  NULL,
	  NULL,
	  NULL,
	  NULL,
	  lm_data_resp_netwkstagetinfo,
	  lm_null },

	{ API_NetWkstaUserLogon,
	  lm_params_req_netwkstauserlogon,
	  NULL,
	  NULL,
	  lm_null,
	  lm_null,
	  lm_params_resp_netwkstauserlogon,
	  NULL,
	  NULL,
	  NULL,
	  NULL,
	  lm_data_resp_netwkstauserlogon,
	  lm_null },

	{ API_NetWkstaUserLogoff,
	  lm_params_req_netwkstauserlogoff,
	  NULL,
	  NULL,
	  lm_null,
	  lm_null,
	  lm_params_resp_netwkstauserlogoff,
	  NULL,
	  NULL,
	  NULL,
	  NULL,
	  lm_data_resp_netwkstauserlogoff,
	  lm_null },

	{ API_SamOEMChgPasswordUser2_P,
	  lm_params_req_samoemchangepassword,
	  NULL,
	  NULL,
	  lm_data_req_samoemchangepassword,
	  lm_null,
	  lm_null,
	  NULL,
	  NULL,
	  NULL,
	  NULL,
	  lm_null_list,
	  lm_null },

	{ API_NetServerEnum3,
	  lm_params_req_netserverenum3,
	  NULL,
	  NULL,
	  lm_null,
	  lm_null,
	  lm_params_resp_netserverenum2,
	  "Servers",
	  &ett_lanman_servers,
	  netserverenum2_server_entry,
	  &ett_lanman_server,
	  lm_data_serverinfo,
	  lm_null },

	{ -1,
	  lm_null,
	  NULL,
	  NULL,
	  lm_null,
	  lm_null,
	  lm_null,
	  NULL,
	  NULL,
	  NULL,
	  &ett_lanman_unknown_entry,
	  lm_null_list,
	  lm_null }
};

static const struct lanman_desc *
find_lanman(int lanman_num)
{
	int i;

	for (i = 0; lmd[i].lanman_num != -1; i++) {
		if (lmd[i].lanman_num == lanman_num)
			break;
	}
	return &lmd[i];
}

static const guchar *
get_count(const guchar *desc, int *countp)
{
	int count = 0;
	guchar c;

	if (!isdigit(*desc)) {
		*countp = 1;	/* no count was supplied */
		return desc;
	}

	while ((c = *desc) != '\0' && isdigit(c)) {
		count = (count * 10) + c - '0';
		desc++;
	}

	*countp = count;	/* XXX - what if it's 0? */
	return desc;
}

static int
dissect_request_parameters(tvbuff_t *tvb, int offset, packet_info *pinfo,
    proto_tree *tree, const guchar *desc, const item_t *items,
    gboolean *has_data_p)
{
	guint c;
	guint16 WParam;
	guint32 LParam;
	guint string_len;
	int count;

	*has_data_p = FALSE;
	while ((c = *desc++) != '\0') {
		switch (c) {

		case 'W':
			/*
			 * A 16-bit word value in the request.
			 */
			if (items->func == NULL) {
				/*
				 * We've run out of items in the table;
				 * fall back on the default.
				 */
				offset = add_word_param(tvb, offset, 0, pinfo,
				    tree, 0, -1);
			} else if (items->type != PARAM_WORD) {
				/*
				 * Descriptor character is 'W', but this
				 * isn't a word parameter.
				 */
				WParam = tvb_get_letohs(tvb, offset);
				proto_tree_add_text(tree, tvb, offset, 2,
				    "%s: Value is %u (0x%04X), type is wrong (W)",
				    (*items->hf_index == -1) ?
				      "Word Param" :
				      proto_registrar_get_name(*items->hf_index),
				    WParam, WParam);
				offset += 2;
				items++;
			} else {
				offset = (*items->func)(tvb, offset, 0, pinfo,
				    tree, 0, *items->hf_index);
				items++;
			}
			break;

		case 'D':
			/*
			 * A 32-bit doubleword value in the request.
			 */
			if (items->func == NULL) {
				/*
				 * We've run out of items in the table;
				 * fall back on the default.
				 */
				offset = add_dword_param(tvb, offset, 0, pinfo,
				    tree, 0, -1);
			} else if (items->type != PARAM_DWORD) {
				/*
				 * Descriptor character is 'D', but this
				 * isn't a doubleword parameter.
				 */
				LParam = tvb_get_letohl(tvb, offset);
				proto_tree_add_text(tree, tvb, offset, 2,
				    "%s: Value is %u (0x%08X), type is wrong (D)",
				    (*items->hf_index == -1) ?
				      "Doubleword Param" :
				      proto_registrar_get_name(*items->hf_index),
				    LParam, LParam);
				offset += 4;
				items++;
			} else {
				offset = (*items->func)(tvb, offset, 0, pinfo,
				    tree, 0, *items->hf_index);
				items++;
			}
			break;

		case 'b':
			/*
			 * A byte or multi-byte value in the request.
			 */
			desc = get_count(desc, &count);
			if (items->func == NULL) {
				/*
				 * We've run out of items in the table;
				 * fall back on the default.
				 */
				offset = add_byte_param(tvb, offset, count,
				    pinfo, tree, 0, -1);
			} else if (items->type != PARAM_BYTES) {
				/*
				 * Descriptor character is 'b', but this
				 * isn't a byte/bytes parameter.
				 */
				proto_tree_add_text(tree, tvb, offset, count,
				    "%s: Value is %s, type is wrong (b)",
				    (*items->hf_index == -1) ?
				      "Byte Param" :
				      proto_registrar_get_name(*items->hf_index),
				    tvb_bytes_to_str(tvb, offset, count));
				offset += count;
				items++;
			} else {
				offset = (*items->func)(tvb, offset, count,
				    pinfo, tree, 0, *items->hf_index);
				items++;
			}
 			break;

		case 'O':
			/*
			 * A null pointer.
			 */
			if (items->func == NULL) {
				/*
				 * We've run out of items in the table;
				 * fall back on the default.
				 */
				add_null_pointer_param(tvb, offset, 0,
				    pinfo, tree, 0, -1);
			} else {
				/*
				 * If "*items->hf_index" is -1, this is
				 * a reserved must-be-null field; don't
				 * clutter the protocol tree by putting
				 * it in.
				 */
				if (*items->hf_index != -1) {
					add_null_pointer_param(tvb,
					    offset, 0, pinfo, tree, 0,
					    *items->hf_index);
				}
				items++;
			}
			break;

		case 'z':
			/*
			 * A null-terminated ASCII string.
			 */
			if (items->func == NULL) {
				/*
				 * We've run out of items in the table;
				 * fall back on the default.
				 */
				offset = add_string_param(tvb, offset, 0,
				    pinfo, tree, 0, -1);
			} else if (items->type != PARAM_STRINGZ) {
				/*
				 * Descriptor character is 'z', but this
				 * isn't a string parameter.
				 */
				string_len = tvb_strsize(tvb, offset);
				proto_tree_add_text(tree, tvb, offset, string_len,
				    "%s: Value is %s, type is wrong (z)",
				    (*items->hf_index == -1) ?
				      "String Param" :
				      proto_registrar_get_name(*items->hf_index),
				    tvb_format_text(tvb, offset, string_len));
				offset += string_len;
				items++;
			} else {
				offset = (*items->func)(tvb, offset, 0,
				    pinfo, tree, 0, *items->hf_index);
				items++;
			}
			break;

		case 'F':
			/*
			 * One or more pad bytes.
			 */
			desc = get_count(desc, &count);
			proto_tree_add_text(tree, tvb, offset, count,
			    "%s", "Padding");
			offset += count;
			break;

		case 'L':
			/*
			 * 16-bit receive buffer length.
			 */
			proto_tree_add_item(tree, hf_recv_buf_len, tvb,
			    offset, 2, TRUE);
			offset += 2;
			break;

		case 's':
			/*
			 * 32-bit send buffer offset.
			 * This appears not to be sent over the wire.
			 */
			*has_data_p = TRUE;
			break;

		case 'T':
			/*
			 * 16-bit send buffer length.
			 */
			proto_tree_add_item(tree, hf_send_buf_len, tvb,
			    offset, 2, TRUE);
			offset += 2;
			break;

		default:
			break;
		}
	}
	return offset;
}

static int
dissect_response_parameters(tvbuff_t *tvb, int offset, packet_info *pinfo,
    proto_tree *tree, const guchar *desc, const item_t *items,
    gboolean *has_data_p, gboolean *has_ent_count_p, guint16 *ent_count_p)
{
	guint c;
	guint16 WParam;
	guint32 LParam;
	int count;

	*has_data_p = FALSE;
	*has_ent_count_p = FALSE;
	while ((c = *desc++) != '\0') {
		switch (c) {

		case 'r':
			/*
			 * 32-bit receive buffer offset.
			 */
			*has_data_p = TRUE;
			break;

		case 'g':
			/*
			 * A byte or series of bytes is returned.
			 */
			desc = get_count(desc, &count);
			if (items->func == NULL) {
				/*
				 * We've run out of items in the table;
				 * fall back on the default.
				 */
				offset = add_byte_param(tvb, offset, count,
				    pinfo, tree, 0, -1);
			} else if (items->type != PARAM_BYTES) {
				/*
				 * Descriptor character is 'b', but this
				 * isn't a byte/bytes parameter.
				 */
				proto_tree_add_text(tree, tvb, offset, count,
				    "%s: Value is %s, type is wrong (g)",
				    (*items->hf_index == -1) ?
				      "Byte Param" :
				      proto_registrar_get_name(*items->hf_index),
				    tvb_bytes_to_str(tvb, offset, count));
				offset += count;
				items++;
			} else {
				offset = (*items->func)(tvb, offset, count,
				    pinfo, tree, 0, *items->hf_index);
				items++;
			}
			break;

		case 'h':
			/*
			 * A 16-bit word is received.
			 */
			if (items->func == NULL) {
				/*
				 * We've run out of items in the table;
				 * fall back on the default.
				 */
				offset = add_word_param(tvb, offset, 0, pinfo,
				    tree, 0, -1);
			} else if (items->type != PARAM_WORD) {
				/*
				 * Descriptor character is 'h', but this
				 * isn't a word parameter.
				 */
				WParam = tvb_get_letohs(tvb, offset);
				proto_tree_add_text(tree, tvb, offset, 2,
				    "%s: Value is %u (0x%04X), type is wrong (W)",
				    (*items->hf_index == -1) ?
				      "Word Param" :
				      proto_registrar_get_name(*items->hf_index),
				    WParam, WParam);
				offset += 2;
				items++;
			} else {
				offset = (*items->func)(tvb, offset, 0, pinfo,
				    tree, 0, *items->hf_index);
				items++;
			}
			break;

		case 'i':
			/*
			 * A 32-bit doubleword is received.
			 */
			if (items->func == NULL) {
				/*
				 * We've run out of items in the table;
				 * fall back on the default.
				 */
				offset = add_dword_param(tvb, offset, 0, pinfo,
				    tree, 0, -1);
			} else if (items->type != PARAM_DWORD) {
				/*
				 * Descriptor character is 'i', but this
				 * isn't a doubleword parameter.
				 */
				LParam = tvb_get_letohl(tvb, offset);
				proto_tree_add_text(tree, tvb, offset, 2,
				    "%s: Value is %u (0x%08X), type is wrong (i)",
				    (*items->hf_index == -1) ?
				      "Doubleword Param" :
				      proto_registrar_get_name(*items->hf_index),
				    LParam, LParam);
				offset += 4;
				items++;
			} else {
				offset = (*items->func)(tvb, offset, 0, pinfo,
				    tree, 0, *items->hf_index);
				items++;
			}
			break;

		case 'e':
			/*
			 * A 16-bit entry count is returned.
			 */
			WParam = tvb_get_letohs(tvb, offset);
			proto_tree_add_uint(tree, hf_ecount, tvb, offset, 2,
			    WParam);
			offset += 2;
			*has_ent_count_p = TRUE;
			*ent_count_p = WParam;  /* Save this for later retrieval */
			break;

		default:
			break;
		}
	}
	return offset;
}

static int
dissect_transact_data(tvbuff_t *tvb, int offset, int convert,
    packet_info *pinfo, proto_tree *tree, const guchar *desc,
    const item_t *items, guint16 *aux_count_p)
{
	guint c;
	guint16 WParam;
	guint32 LParam;
	int count;
	int cptr;
	const char *string;
	gint string_len;

	if (aux_count_p != NULL)
		*aux_count_p = 0;

	while ((c = *desc++) != '\0') {
		switch (c) {

		case 'W':
			/*
			 * A 16-bit word value.
			 * XXX - handle the count?
			 */
			desc = get_count(desc, &count);
			if (items->func == NULL) {
				/*
				 * We've run out of items in the table;
				 * fall back on the default.
				 */
				offset = add_word_param(tvb, offset, 0, pinfo,
				    tree, convert, -1);
			} else if (items->type != PARAM_WORD) {
				/*
				 * Descriptor character is 'W', but this
				 * isn't a word parameter.
				 */
				WParam = tvb_get_letohs(tvb, offset);
				proto_tree_add_text(tree, tvb, offset, 2,
				    "%s: Value is %u (0x%04X), type is wrong (W)",
				    (*items->hf_index == -1) ?
				      "Word Param" :
				      proto_registrar_get_name(*items->hf_index),
				    WParam, WParam);
				offset += 2;
				items++;
			} else {
				offset = (*items->func)(tvb, offset, 0, pinfo,
				    tree, convert, *items->hf_index);
				items++;
			}
			break;

		case 'D':
			/*
			 * A 32-bit doubleword value.
			 * XXX - handle the count?
			 */
			desc = get_count(desc, &count);
			if (items->func == NULL) {
				/*
				 * We've run out of items in the table;
				 * fall back on the default.
				 */
				offset = add_dword_param(tvb, offset, 0, pinfo,
				    tree, convert, -1);
			} else if (items->type != PARAM_DWORD) {
				/*
				 * Descriptor character is 'D', but this
				 * isn't a doubleword parameter.
				 */
				LParam = tvb_get_letohl(tvb, offset);
				proto_tree_add_text(tree, tvb, offset, 2,
				    "%s: Value is %u (0x%08X), type is wrong (D)",
				    (*items->hf_index == -1) ?
				      "Doubleword Param" :
				      proto_registrar_get_name(*items->hf_index),
				    LParam, LParam);
				offset += 4;
				items++;
			} else {
				offset = (*items->func)(tvb, offset, 0, pinfo,
				    tree, convert, *items->hf_index);
				items++;
			}
			break;

		case 'B':
			/*
			 * A byte or multi-byte value.
			 */
			desc = get_count(desc, &count);
			if (items->func == NULL) {
				/*
				 * We've run out of items in the table;
				 * fall back on the default.
				 */
				offset = add_byte_param(tvb, offset, count,
				    pinfo, tree, convert, -1);
			} else if (items->type != PARAM_BYTES) {
				/*
				 * Descriptor character is 'B', but this
				 * isn't a byte/bytes parameter.
				 */
				proto_tree_add_text(tree, tvb, offset, count,
				    "%s: Value is %s, type is wrong (B)",
				    (*items->hf_index == -1) ?
				      "Byte Param" :
				      proto_registrar_get_name(*items->hf_index),
				    tvb_bytes_to_str(tvb, offset, count));
				offset += count;
				items++;
			} else {
				offset = (*items->func)(tvb, offset, count,
				    pinfo, tree, convert, *items->hf_index);
				items++;
			}
			break;

		case 'O':
			/*
			 * A null pointer.
			 */
			if (items->func == NULL) {
				/*
				 * We've run out of items in the table;
				 * fall back on the default.
				 */
				add_null_pointer_param(tvb, offset, 0,
				    pinfo, tree, convert, -1);
			} else {
				/*
				 * If "*items->hf_index" is -1, this is
				 * a reserved must-be-null field; don't
				 * clutter the protocol tree by putting
				 * it in.
				 */
				if (*items->hf_index != -1) {
					add_null_pointer_param(tvb,
					    offset, 0, pinfo, tree, convert,
					    *items->hf_index);
				}
				items++;
			}
			break;

		case 'z':
			/*
			 * A pointer to a null-terminated ASCII string.
			 */
			if (items->func == NULL) {
				/*
				 * We've run out of items in the table;
				 * fall back on the default.
				 */
				offset = add_stringz_pointer_param(tvb, offset,
				    0, pinfo, tree, convert, -1);
			} else if (items->type != PARAM_STRINGZ) {
				/*
				 * Descriptor character is 'z', but this
				 * isn't a string parameter.
				 */
				string = get_stringz_pointer_value(tvb, offset,
				    convert, &cptr, &string_len);
				offset += 4;
				proto_tree_add_text(tree, tvb, cptr, string_len,
				    "%s: Value is %s, type is wrong (z)",
				    (*items->hf_index == -1) ?
				      "String Param" :
				      proto_registrar_get_name(*items->hf_index),
				    string);
				items++;
			} else {
				offset = (*items->func)(tvb, offset, 0,
				    pinfo, tree, convert, *items->hf_index);
				items++;
			}
			break;

		case 'b':
			/*
			 * A pointer to a byte or multi-byte value.
			 */
			desc = get_count(desc, &count);
			if (items->func == NULL) {
				/*
				 * We've run out of items in the table;
				 * fall back on the default.
				 */
				offset = add_bytes_pointer_param(tvb, offset,
				    count, pinfo, tree, convert, -1);
			} else if (items->type != PARAM_BYTES) {
				/*
				 * Descriptor character is 'b', but this
				 * isn't a byte/bytes parameter.
				 */
				cptr = (tvb_get_letohl(tvb, offset)&0xffff)-convert;
				offset += 4;
				proto_tree_add_text(tree, tvb, offset, count,
				    "%s: Value is %s, type is wrong (b)",
				    (*items->hf_index == -1) ?
				      "Byte Param" :
				      proto_registrar_get_name(*items->hf_index),
				    tvb_bytes_to_str(tvb, cptr, count));
				items++;
			} else {
				offset = (*items->func)(tvb, offset, count,
				    pinfo, tree, convert, *items->hf_index);
				items++;
			}
			break;

		case 'N':
			/*
			 * 16-bit auxiliary data structure count.
			 * XXX - hf_acount?
			 */
			WParam = tvb_get_letohs(tvb, offset);
			proto_tree_add_text(tree, tvb, offset, 2,
			    "%s: %u (0x%04X)",
			    "Auxiliary data structure count",
			    WParam, WParam);
			offset += 2;
			if (aux_count_p != NULL)
				*aux_count_p = WParam;  /* Save this for later retrieval */
			break;

		default:
			break;
		}
	}
	return offset;
}

static const value_string commands[] = {
	{API_NetShareEnum,			"NetShareEnum"},
	{API_NetShareGetInfo,			"NetShareGetInfo"},
	{API_NetShareSetInfo,			"NetShareSetInfo"},
	{API_NetShareAdd,			"NetShareAdd"},
	{API_NetShareDel,			"NetShareDel"},
	{API_NetShareCheck,			"NetShareCheck"},
	{API_NetSessionEnum,			"NetSessionEnum"},
	{API_NetSessionGetInfo,			"NetSessionGetInfo"},
	{API_NetSessionDel,			"NetSessionDel"},
	{API_WconnectionEnum,			"NetConnectionEnum"},
	{API_NetFileEnum,			"NetFileEnum"},
	{API_NetFileGetInfo,			"NetFileGetInfo"},
	{API_NetFileClose,			"NetFileClose"},
	{API_NetServerGetInfo,			"NetServerGetInfo"},
	{API_NetServerSetInfo,			"NetServerSetInfo"},
	{API_NetServerDiskEnum,			"NetServerDiskEnum"},
	{API_NetServerAdminCommand,		"NetServerAdminCommand"},
	{API_NetAuditOpen,			"NetAuditOpen"},
	{API_NetAuditClear,			"NetAuditClear"},
	{API_NetErrorLogOpen,			"NetErrorLogOpen"},
	{API_NetErrorLogClear,			"NetErrorLogClear"},
	{API_NetCharDevEnum,			"NetCharDevEnum"},
	{API_NetCharDevGetInfo,			"NetCharDevGetInfo"},
	{API_NetCharDevControl,			"NetCharDevControl"},
	{API_NetCharDevQEnum,			"NetCharDevQEnum"},
	{API_NetCharDevQGetInfo,		"NetCharDevQGetInfo"},
	{API_NetCharDevQSetInfo,		"NetCharDevQSetInfo"},
	{API_NetCharDevQPurge,			"NetCharDevQPurge"},
	{API_NetCharDevQPurgeSelf,		"NetCharDevQPurgeSelf"},
	{API_NetMessageNameEnum,		"NetMessageNameEnum"},
	{API_NetMessageNameGetInfo,		"NetMessageNameGetInfo"},
	{API_NetMessageNameAdd,			"NetMessageNameAdd"},
	{API_NetMessageNameDel,			"NetMessageNameDel"},
	{API_NetMessageNameFwd,			"NetMessageNameFwd"},
	{API_NetMessageNameUnFwd,		"NetMessageNameUnFwd"},
	{API_NetMessageBufferSend,		"NetMessageBufferSend"},
	{API_NetMessageFileSend,		"NetMessageFileSend"},
	{API_NetMessageLogFileSet,		"NetMessageLogFileSet"},
	{API_NetMessageLogFileGet,		"NetMessageLogFileGet"},
	{API_NetServiceEnum,			"NetServiceEnum"},
	{API_NetServiceInstall,			"NetServiceInstall"},
	{API_NetServiceControl,			"NetServiceControl"},
	{API_NetAccessEnum,			"NetAccessEnum"},
	{API_NetAccessGetInfo,			"NetAccessGetInfo"},
	{API_NetAccessSetInfo,			"NetAccessSetInfo"},
	{API_NetAccessAdd,			"NetAccessAdd"},
	{API_NetAccessDel,			"NetAccessDel"},
	{API_NetGroupEnum,			"NetGroupEnum"},
	{API_NetGroupAdd,			"NetGroupAdd"},
	{API_NetGroupDel,			"NetGroupDel"},
	{API_NetGroupAddUser,			"NetGroupAddUser"},
	{API_NetGroupDelUser,			"NetGroupDelUser"},
	{API_NetGroupGetUsers,			"NetGroupGetUsers"},
	{API_NetUserEnum,			"NetUserEnum"},
	{API_NetUserAdd,			"NetUserAdd"},
	{API_NetUserDel,			"NetUserDel"},
	{API_NetUserGetInfo,			"NetUserGetInfo"},
	{API_NetUserSetInfo,			"NetUserSetInfo"},
	{API_NetUserPasswordSet,		"NetUserPasswordSet"},
	{API_NetUserGetGroups,			"NetUserGetGroups"},
	{API_NetWkstaSetUID,			"NetWkstaSetUID"},
	{API_NetWkstaGetInfo,			"NetWkstaGetInfo"},
	{API_NetWkstaSetInfo,			"NetWkstaSetInfo"},
	{API_NetUseEnum,			"NetUseEnum"},
	{API_NetUseAdd,				"NetUseAdd"},
	{API_NetUseDel,				"NetUseDel"},
	{API_NetUseGetInfo,			"NetUseGetInfo"},
	{API_WPrintQEnum,			"WPrintQEnum"},
	{API_WPrintQGetInfo,			"WPrintQGetInfo"},
	{API_WPrintQSetInfo,			"WPrintQSetInfo"},
	{API_WPrintQAdd,			"WPrintQAdd"},
	{API_WPrintQDel,			"WPrintQDel"},
	{API_WPrintQPause,			"WPrintQPause"},
	{API_WPrintQContinue,			"WPrintQContinue"},
	{API_WPrintJobEnum,			"WPrintJobEnum"},
	{API_WPrintJobGetInfo,			"WPrintJobGetInfo"},
	{API_WPrintJobSetInfo_OLD,		"WPrintJobSetInfo_OLD"},
	{API_WPrintJobDel,			"WPrintJobDel"},
	{API_WPrintJobPause,			"WPrintJobPause"},
	{API_WPrintJobContinue,			"WPrintJobContinue"},
	{API_WPrintDestEnum,			"WPrintDestEnum"},
	{API_WPrintDestGetInfo,			"WPrintDestGetInfo"},
	{API_WPrintDestControl,			"WPrintDestControl"},
	{API_NetProfileSave,			"NetProfileSave"},
	{API_NetProfileLoad,			"NetProfileLoad"},
	{API_NetStatisticsGet,			"NetStatisticsGet"},
	{API_NetStatisticsClear,		"NetStatisticsClear"},
	{API_NetRemoteTOD,			"NetRemoteTOD"},
	{API_WNetBiosEnum,			"WNetBiosEnum"},
	{API_WNetBiosGetInfo,			"WNetBiosGetInfo"},
	{API_NetServerEnum,			"NetServerEnum"},
	{API_I_NetServerEnum,			"I_NetServerEnum"},
	{API_NetServiceGetInfo,			"NetServiceGetInfo"},
	{API_WPrintQPurge,			"WPrintQPurge"},
	{API_NetServerEnum2,			"NetServerEnum2"},
	{API_NetAccessGetUserPerms,		"NetAccessGetUserPerms"},
	{API_NetGroupGetInfo,			"NetGroupGetInfo"},
	{API_NetGroupSetInfo,			"NetGroupSetInfo"},
	{API_NetGroupSetUsers,			"NetGroupSetUsers"},
	{API_NetUserSetGroups,			"NetUserSetGroups"},
	{API_NetUserModalsGet,			"NetUserModalsGet"},
	{API_NetUserModalsSet,			"NetUserModalsSet"},
	{API_NetFileEnum2,			"NetFileEnum2"},
	{API_NetUserAdd2,			"NetUserAdd2"},
	{API_NetUserSetInfo2,			"NetUserSetInfo2"},
	{API_NetUserPasswordSet2,		"SetUserPassword"},
	{API_I_NetServerEnum2,			"I_NetServerEnum2"},
	{API_NetConfigGet2,			"NetConfigGet2"},
	{API_NetConfigGetAll2,			"NetConfigGetAll2"},
	{API_NetGetDCName,			"NetGetDCName"},
	{API_NetHandleGetInfo,			"NetHandleGetInfo"},
	{API_NetHandleSetInfo,			"NetHandleSetInfo"},
	{API_NetStatisticsGet2,			"NetStatisticsGet2"},
	{API_WBuildGetInfo,			"WBuildGetInfo"},
	{API_NetFileGetInfo2,			"NetFileGetInfo2"},
	{API_NetFileClose2,			"NetFileClose2"},
	{API_NetServerReqChallenge,		"NetServerReqChallenge"},
	{API_NetServerAuthenticate,		"NetServerAuthenticate"},
	{API_NetServerPasswordSet,		"NetServerPasswordSet"},
	{API_WNetAccountDeltas,			"WNetAccountDeltas"},
	{API_WNetAccountSync,			"WNetAccountSync"},
	{API_NetUserEnum2,			"NetUserEnum2"},
	{API_NetWkstaUserLogon,			"NetWkstaUserLogon"},
	{API_NetWkstaUserLogoff,		"NetWkstaUserLogoff"},
	{API_NetLogonEnum,			"NetLogonEnum"},
	{API_NetErrorLogRead,			"NetErrorLogRead"},
	{API_I_NetPathType,			"I_NetPathType"},
	{API_I_NetPathCanonicalize,		"I_NetPathCanonicalize"},
	{API_I_NetPathCompare,			"I_NetPathCompare"},
	{API_I_NetNameValidate,			"I_NetNameValidate"},
	{API_I_NetNameCanonicalize,		"I_NetNameCanonicalize"},
	{API_I_NetNameCompare,			"I_NetNameCompare"},
	{API_NetAuditRead,			"NetAuditRead"},
	{API_WPrintDestAdd,			"WPrintDestAdd"},
	{API_WPrintDestSetInfo,			"WPrintDestSetInfo"},
	{API_WPrintDestDel,			"WPrintDestDel"},
	{API_NetUserValidate2,			"NetUserValidate2"},
	{API_WPrintJobSetInfo,			"WPrintJobSetInfo"},
	{API_TI_NetServerDiskEnum,		"TI_NetServerDiskEnum"},
	{API_TI_NetServerDiskGetInfo,		"TI_NetServerDiskGetInfo"},
	{API_TI_FTVerifyMirror,			"TI_FTVerifyMirror"},
	{API_TI_FTAbortVerify,			"TI_FTAbortVerify"},
	{API_TI_FTGetInfo,			"TI_FTGetInfo"},
	{API_TI_FTSetInfo,			"TI_FTSetInfo"},
	{API_TI_FTLockDisk,			"TI_FTLockDisk"},
	{API_TI_FTFixError,			"TI_FTFixError"},
	{API_TI_FTAbortFix,			"TI_FTAbortFix"},
	{API_TI_FTDiagnoseError,		"TI_FTDiagnoseError"},
	{API_TI_FTGetDriveStats,		"TI_FTGetDriveStats"},
	{API_TI_FTErrorGetInfo,			"TI_FTErrorGetInfo"},
	{API_NetAccessCheck,			"NetAccessCheck"},
	{API_NetAlertRaise,			"NetAlertRaise"},
	{API_NetAlertStart,			"NetAlertStart"},
	{API_NetAlertStop,			"NetAlertStop"},
	{API_NetAuditWrite,			"NetAuditWrite"},
	{API_NetIRemoteAPI,			"NetIRemoteAPI"},
	{API_NetServiceStatus,			"NetServiceStatus"},
	{API_I_NetServerRegister,		"I_NetServerRegister"},
	{API_I_NetServerDeregister,		"I_NetServerDeregister"},
	{API_I_NetSessionEntryMake,		"I_NetSessionEntryMake"},
	{API_I_NetSessionEntryClear,		"I_NetSessionEntryClear"},
	{API_I_NetSessionEntryGetInfo,		"I_NetSessionEntryGetInfo"},
	{API_I_NetSessionEntrySetInfo,		"I_NetSessionEntrySetInfo"},
	{API_I_NetConnectionEntryMake,		"I_NetConnectionEntryMake"},
	{API_I_NetConnectionEntryClear,		"I_NetConnectionEntryClear"},
	{API_I_NetConnectionEntrySetInfo,	"I_NetConnectionEntrySetInfo"},
	{API_I_NetConnectionEntryGetInfo,	"I_NetConnectionEntryGetInfo"},
	{API_I_NetFileEntryMake,		"I_NetFileEntryMake"},
	{API_I_NetFileEntryClear,		"I_NetFileEntryClear"},
	{API_I_NetFileEntrySetInfo,		"I_NetFileEntrySetInfo"},
	{API_I_NetFileEntryGetInfo,		"I_NetFileEntryGetInfo"},
	{API_AltSrvMessageBufferSend,		"AltSrvMessageBufferSend"},
	{API_AltSrvMessageFileSend,		"AltSrvMessageFileSend"},
	{API_wI_NetRplWkstaEnum,		"wI_NetRplWkstaEnum"},
	{API_wI_NetRplWkstaGetInfo,		"wI_NetRplWkstaGetInfo"},
	{API_wI_NetRplWkstaSetInfo,		"wI_NetRplWkstaSetInfo"},
	{API_wI_NetRplWkstaAdd,			"wI_NetRplWkstaAdd"},
	{API_wI_NetRplWkstaDel,			"wI_NetRplWkstaDel"},
	{API_wI_NetRplProfileEnum,		"wI_NetRplProfileEnum"},
	{API_wI_NetRplProfileGetInfo,		"wI_NetRplProfileGetInfo"},
	{API_wI_NetRplProfileSetInfo,		"wI_NetRplProfileSetInfo"},
	{API_wI_NetRplProfileAdd,		"wI_NetRplProfileAdd"},
	{API_wI_NetRplProfileDel,		"wI_NetRplProfileDel"},
	{API_wI_NetRplProfileClone,		"wI_NetRplProfileClone"},
	{API_wI_NetRplBaseProfileEnum,		"wI_NetRplBaseProfileEnum"},
	{API_WIServerSetInfo,			"WIServerSetInfo"},
	{API_WPrintDriverEnum,			"WPrintDriverEnum"},
	{API_WPrintQProcessorEnum,		"WPrintQProcessorEnum"},
	{API_WPrintPortEnum,			"WPrintPortEnum"},
	{API_WNetWriteUpdateLog,		"WNetWriteUpdateLog"},
	{API_WNetAccountUpdate,			"WNetAccountUpdate"},
	{API_WNetAccountConfirmUpdate,		"WNetAccountConfirmUpdate"},
	{API_NetConfigSet,			"NetConfigSet"},
	{API_WAccountsReplicate,		"WAccountsReplicate"},
	{API_SamOEMChgPasswordUser2_P,		"SamOEMChangePassword"},
	{API_NetServerEnum3,			"NetServerEnum3"},
	{API_WPrintDriverGetInfo,		"WPrintDriverGetInfo"},
	{API_WPrintDriverSetInfo,		"WPrintDriverSetInfo"},
	{API_NetAliasAdd,			"NetAliasAdd"},
	{API_NetAliasDel,			"NetAliasDel"},
	{API_NetAliasGetInfo,			"NetAliasGetInfo"},
	{API_NetAliasSetInfo,			"NetAliasSetInfo"},
	{API_NetAliasEnum,			"NetAliasEnum"},
	{API_NetUserGetLogonAsn,		"NetUserGetLogonAsn"},
	{API_NetUserSetLogonAsn,		"NetUserSetLogonAsn"},
	{API_NetUserGetAppSel,			"NetUserGetAppSel"},
	{API_NetUserSetAppSel,			"NetUserSetAppSel"},
	{API_NetAppAdd,				"NetAppAdd"},
	{API_NetAppDel,				"NetAppDel"},
	{API_NetAppGetInfo,			"NetAppGetInfo"},
	{API_NetAppSetInfo,			"NetAppSetInfo"},
	{API_NetAppEnum,			"NetAppEnum"},
	{API_NetUserDCDBInit,			"NetUserDCDBInit"},
	{API_NetDASDAdd,			"NetDASDAdd"},
	{API_NetDASDDel,			"NetDASDDel"},
	{API_NetDASDGetInfo,			"NetDASDGetInfo"},
	{API_NetDASDSetInfo,			"NetDASDSetInfo"},
	{API_NetDASDEnum,			"NetDASDEnum"},
	{API_NetDASDCheck,			"NetDASDCheck"},
	{API_NetDASDCtl,			"NetDASDCtl"},
	{API_NetUserRemoteLogonCheck,		"NetUserRemoteLogonCheck"},
	{API_NetUserPasswordSet3,		"NetUserPasswordSet3"},
	{API_NetCreateRIPLMachine,		"NetCreateRIPLMachine"},
	{API_NetDeleteRIPLMachine,		"NetDeleteRIPLMachine"},
	{API_NetGetRIPLMachineInfo,		"NetGetRIPLMachineInfo"},
	{API_NetSetRIPLMachineInfo,		"NetSetRIPLMachineInfo"},
	{API_NetEnumRIPLMachine,		"NetEnumRIPLMachine"},
	{API_I_ShareAdd,			"I_ShareAdd"},
	{API_I_AliasEnum,			"I_AliasEnum"},
	{API_NetAccessApply,			"NetAccessApply"},
	{API_WPrt16Query,			"WPrt16Query"},
	{API_WPrt16Set,				"WPrt16Set"},
	{API_NetUserDel100,			"NetUserDel100"},
	{API_NetUserRemoteLogonCheck2,		"NetUserRemoteLogonCheck2"},
	{API_WRemoteTODSet,			"WRemoteTODSet"},
	{API_WPrintJobMoveAll,			"WPrintJobMoveAll"},
	{API_W16AppParmAdd,			"W16AppParmAdd"},
	{API_W16AppParmDel,			"W16AppParmDel"},
	{API_W16AppParmGet,			"W16AppParmGet"},
	{API_W16AppParmSet,			"W16AppParmSet"},
	{API_W16RIPLMachineCreate,		"W16RIPLMachineCreate"},
	{API_W16RIPLMachineGetInfo,		"W16RIPLMachineGetInfo"},
	{API_W16RIPLMachineSetInfo,		"W16RIPLMachineSetInfo"},
	{API_W16RIPLMachineEnum,		"W16RIPLMachineEnum"},
	{API_W16RIPLMachineListParmEnum,	"W16RIPLMachineListParmEnum"},
	{API_W16RIPLMachClassGetInfo,		"W16RIPLMachClassGetInfo"},
	{API_W16RIPLMachClassEnum,		"W16RIPLMachClassEnum"},
	{API_W16RIPLMachClassCreate,		"W16RIPLMachClassCreate"},
	{API_W16RIPLMachClassSetInfo,		"W16RIPLMachClassSetInfo"},
	{API_W16RIPLMachClassDelete,		"W16RIPLMachClassDelete"},
	{API_W16RIPLMachClassLPEnum,		"W16RIPLMachClassLPEnum"},
	{API_W16RIPLMachineDelete,		"W16RIPLMachineDelete"},
	{API_W16WSLevelGetInfo,			"W16WSLevelGetInfo"},
	{API_NetServerNameAdd,			"NetServerNameAdd"},
	{API_NetServerNameDel,			"NetServerNameDel"},
	{API_NetServerNameEnum,			"NetServerNameEnum"},
	{API_I_WDASDEnum,			"I_WDASDEnum"},
	{API_I_WDASDEnumTerminate,		"I_WDASDEnumTerminate"},
	{API_I_WDASDSetInfo2,			"I_WDASDSetInfo2"},
	{0,					NULL}
};

static void
dissect_response_data(tvbuff_t *tvb, packet_info *pinfo, int convert,
    proto_tree *tree, struct smb_info *smb_info,
    const struct lanman_desc *lanman, gboolean has_ent_count,
    guint16 ent_count)
{
	smb_transact_info_t *trp;
	const item_list_t *resp_data_list;
	int offset, start_offset;
	const char *label;
	gint ett;
	const item_t *resp_data;
	proto_item *data_item;
	proto_tree *data_tree;
	proto_item *entry_item;
	proto_tree *entry_tree;
	guint i, j;
	guint16 aux_count;

	trp = smb_info->sip->extra_info;

	/*
	 * Find the item table for the matching request's detail level.
	 */
	for (resp_data_list = lanman->resp_data_list;
	    resp_data_list->level != -1; resp_data_list++) {
		if (resp_data_list->level == trp->info_level)
			break;
	}
	resp_data = resp_data_list->item_list;

	offset = 0;
	if (has_ent_count) {
		/*
		 * The data is a list of entries; create a protocol tree item
		 * for it.
		 */
		if (tree) {
			label = lanman->resp_data_entry_list_label;
			if (label == NULL)
				label = "Entries";
			if (lanman->ett_data_entry_list != NULL)
				ett = *lanman->ett_data_entry_list;
			else
				ett = ett_lanman_unknown_entries;
			data_item = proto_tree_add_text(tree, tvb, offset, -1,
			    label);
			data_tree = proto_item_add_subtree(data_item, ett);
		} else {
			data_item = NULL;
			data_tree = NULL;
		}
	} else {
		/*
		 * Just leave it at the top level.
		 */
		data_item = NULL;
		data_tree = tree;
	}

	if (trp->data_descrip == NULL) {
		/*
		 * This could happen if we only dissected
		 * part of the request to which this is a
		 * reply, e.g. if the request was split
		 * across TCP segments and we weren't doing
		 * TCP desegmentation, or if we had a snapshot
		 * length that was too short.
		 *
		 * We can't dissect the data; just show it as raw data or,
		 * if we've already created a top-level item, note that
		 * no descriptor is available.
		 */
		if (has_ent_count) {
			if (data_item != NULL) {
				proto_item_append_text(data_item,
				    " (No descriptor available)");
			}
		} else {
			proto_tree_add_text(data_tree, tvb, offset, -1,
			    "Data (no descriptor available)");
		}
		offset += tvb_length_remaining(tvb, offset);
	} else {
		/*
		 * If we have an entry count, show all the entries,
		 * with each one having a protocol tree item.
		 *
		 * Otherwise, we just show one returned item, with
		 * no protocol tree item.
		 */
		if (!has_ent_count)
			ent_count = 1;
		for (i = 0; i < ent_count; i++) {
			start_offset = offset;
			if (has_ent_count &&
			    lanman->resp_data_element_item != NULL) {
				/*
				 * Create a protocol tree item for the
				 * entry.
				 */
				entry_item =
				    (*lanman->resp_data_element_item)
				      (tvb, data_tree, offset);
				entry_tree = proto_item_add_subtree(
				    entry_item,
				    *lanman->ett_resp_data_element_item);
			} else {
				/*
				 * Just leave it at the current
				 * level.
				 */
				entry_item = NULL;
				entry_tree = data_tree;
			}

			offset = dissect_transact_data(tvb, offset,
			    convert, pinfo, entry_tree,
			    trp->data_descrip, resp_data, &aux_count);

			/* auxiliary data */
			if (trp->aux_data_descrip != NULL) {
				for (j = 0; j < aux_count; j++) {
					offset = dissect_transact_data(
					    tvb, offset, convert,
					    pinfo, entry_tree,
					    trp->data_descrip,
					    lanman->resp_aux_data, NULL);
				}
			}

			if (entry_item != NULL) {
				/*
				 * Set the length of the protocol tree
				 * item for the entry.
				 */
				proto_item_set_len(entry_item,
				    offset - start_offset);
			}
		}
	}

	if (data_item != NULL) {
		/*
		 * Set the length of the protocol tree item
		 * for the data.
		 */
		proto_item_set_len(data_item, offset);
	}
}

static gboolean
dissect_pipe_lanman(tvbuff_t *pd_tvb, tvbuff_t *p_tvb, tvbuff_t *d_tvb,
		    packet_info *pinfo, proto_tree *parent_tree)
{
	smb_info_t *smb_info = pinfo->private_data;
	smb_transact_info_t *trp = NULL;
	int offset = 0, start_offset;
	guint16 cmd;
	guint16 status;
	int convert;
	const struct lanman_desc *lanman;
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	guint descriptor_len;
	const gchar *param_descrip, *data_descrip, *aux_data_descrip = NULL;
	gboolean has_data;
	gboolean has_ent_count;
	guint16 ent_count, aux_count;
	guint i;
	proto_item *data_item;
	proto_tree *data_tree;

	if (smb_info->sip->extra_info_type == SMB_EI_TRI)
		trp = smb_info->sip->extra_info;

	if (!proto_is_protocol_enabled(find_protocol_by_id(proto_smb_lanman)))
		return FALSE;
	if (p_tvb == NULL) {
		/*
		 * Requests must have parameters.
		 */
		return FALSE;
	}
	pinfo->current_proto = "LANMAN";

	if (check_col(pinfo->cinfo, COL_PROTOCOL)) {
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "LANMAN");
	}

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, proto_smb_lanman,
			pd_tvb, 0, -1, FALSE);
		tree = proto_item_add_subtree(item, ett_lanman);
	}

	if (smb_info->request) { /* this is a request */
		/* function code */
		cmd = tvb_get_letohs(p_tvb, offset);
		if (check_col(pinfo->cinfo, COL_INFO)) {
			col_add_fstr(pinfo->cinfo, COL_INFO, "%s Request", val_to_str(cmd, commands, "Unknown Command (%u)"));
		}
		proto_tree_add_uint(tree, hf_function_code, p_tvb, offset, 2,
		    cmd);
		offset += 2;

		if(!trp){
			return FALSE; /* cant dissect this request */
		}

		/*
		 * If we haven't already done so, save the function code in
		 * the structure we were handed, so that it's available to
		 * the code parsing the reply, and initialize the detail
		 * level to -1, meaning "unknown".
		 */
		if (!pinfo->fd->flags.visited) {
			trp->lanman_cmd = cmd;
			trp->info_level = -1;
			trp->param_descrip=NULL;
			trp->data_descrip=NULL;
			trp->aux_data_descrip=NULL;
		}

		/* parameter descriptor */
		descriptor_len = tvb_strsize(p_tvb, offset);
		proto_tree_add_item(tree, hf_param_desc, p_tvb, offset,
		    descriptor_len, TRUE);
		param_descrip = tvb_get_ptr(p_tvb, offset, descriptor_len);
		if (!pinfo->fd->flags.visited) {
			/*
			 * Save the parameter descriptor for future use.
			 */
			DISSECTOR_ASSERT(trp->param_descrip == NULL);
			trp->param_descrip = g_strdup(param_descrip);
		}
		offset += descriptor_len;

		/* return descriptor */
		descriptor_len = tvb_strsize(p_tvb, offset);
		proto_tree_add_item(tree, hf_return_desc, p_tvb, offset,
		    descriptor_len, TRUE);
		data_descrip = tvb_get_ptr(p_tvb, offset, descriptor_len);
		if (!pinfo->fd->flags.visited) {
			/*
			 * Save the return descriptor for future use.
			 */
			DISSECTOR_ASSERT(trp->data_descrip == NULL);
			trp->data_descrip = g_strdup(data_descrip);
		}
		offset += descriptor_len;

		lanman = find_lanman(cmd);

		/* request parameters */
		start_offset = offset;
		offset = dissect_request_parameters(p_tvb, offset, pinfo, tree,
		    param_descrip, lanman->req, &has_data);

		/* auxiliary data descriptor */
		if (tvb_reported_length_remaining(p_tvb, offset) > 0){
			/*
			 * There are more parameters left, so the next
			 * item is the auxiliary data descriptor.
			 */
			descriptor_len = tvb_strsize(p_tvb, offset);
			proto_tree_add_item(tree, hf_aux_data_desc, p_tvb, offset,
			    descriptor_len, TRUE);
			aux_data_descrip = tvb_get_ptr(p_tvb, offset, descriptor_len);
			if (!pinfo->fd->flags.visited) {
				/*
				 * Save the auxiliary data descriptor for
				 * future use.
				 */
				DISSECTOR_ASSERT(trp->aux_data_descrip == NULL);
				trp->aux_data_descrip =
				    g_strdup(aux_data_descrip);
			}
			offset += descriptor_len;
		}

		/* reset offset, we now start dissecting the data area */
		offset = 0;
		if (has_data && d_tvb && tvb_reported_length(d_tvb) != 0) {
			/*
			 * There's a send buffer item in the descriptor
			 * string, and the data count in the transaction
			 * is non-zero, so there's data to dissect.
			 */

			if (lanman->req_data_item != NULL) {
				/*
				 * Create a protocol tree item for the data.
				 */
				data_item = (*lanman->req_data_item)(d_tvb,
				    pinfo, tree, offset);
				data_tree = proto_item_add_subtree(data_item,
				    *lanman->ett_req_data);
			} else {
				/*
				 * Just leave it at the top level.
				 */
				data_item = NULL;
				data_tree = tree;
			}

			/* data */
			offset = dissect_transact_data(d_tvb, offset, -1,
			    pinfo, data_tree, data_descrip, lanman->req_data,
			    &aux_count);	/* XXX - what about strings? */

			/* auxiliary data */
			if (aux_data_descrip != NULL) {
				for (i = 0; i < aux_count; i++) {
					offset = dissect_transact_data(d_tvb,
					    offset, -1, pinfo, data_tree,
					    aux_data_descrip,
					    lanman->req_aux_data, NULL);
				}
			}

			if (data_item != NULL) {
				/*
				 * Set the length of the protocol tree item
				 * for the data.
				 */
				proto_item_set_len(data_item, offset);
			}
		}
	} else {
		/*
		 * This is a response.
		 * Have we seen the request to which it's a response?
		 */
		if (trp == NULL)
			return FALSE;	/* no - can't dissect it */

		/* ok we have seen this one before */

		/* if it looks like an interim response, update COL_INFO and return */
		if( ( (p_tvb==NULL) || (tvb_reported_length(p_tvb)==0) )
		&&  ( (d_tvb==NULL) || (tvb_reported_length(d_tvb)==0) ) ){
			/* command */
			if (check_col(pinfo->cinfo, COL_INFO)) {
				col_add_fstr(pinfo->cinfo, COL_INFO, "%s Interim Response",
					     val_to_str(trp->lanman_cmd, commands, "Unknown Command (%u)"));
			}
			proto_tree_add_uint(tree, hf_function_code, p_tvb, 0, 0, trp->lanman_cmd);
			return TRUE;
		}

		/* command */
		if (check_col(pinfo->cinfo, COL_INFO)) {
			col_add_fstr(pinfo->cinfo, COL_INFO, "%s Response",
				     val_to_str(trp->lanman_cmd, commands, "Unknown Command (%u)"));
		}
		proto_tree_add_uint(tree, hf_function_code, p_tvb, 0, 0,
		    trp->lanman_cmd);

		lanman = find_lanman(trp->lanman_cmd);

		/* response parameters */

		/* status */
		status = tvb_get_letohs(p_tvb, offset);
		proto_tree_add_uint(tree, hf_status, p_tvb, offset, 2, status);
		offset += 2;

		/* convert */
		convert = tvb_get_letohs(p_tvb, offset);
		proto_tree_add_uint(tree, hf_convert, p_tvb, offset, 2, convert);
		offset += 2;

		if (trp->param_descrip == NULL) {
			/*
			 * This could happen if we only dissected
			 * part of the request to which this is a
			 * reply, e.g. if the request was split
			 * across TCP segments and we weren't doing
			 * TCP desegmentation, or if we had a snapshot
			 * length that was too short.
			 *
			 * We can't dissect the parameters; just show them
			 * as raw data.
			 */
			proto_tree_add_text(tree, p_tvb, offset, -1,
			    "Parameters (no descriptor available)");

			/*
			 * We don't know whether we have a receive buffer,
			 * as we don't have the descriptor; just show what
			 * bytes purport to be data.
			 */
			if (d_tvb && tvb_reported_length(d_tvb) > 0) {
				proto_tree_add_text(tree, d_tvb, 0, -1,
				    "Data (no descriptor available)");
			}
		} else {
			/* rest of the parameters */
			offset = dissect_response_parameters(p_tvb, offset,
			    pinfo, tree, trp->param_descrip, lanman->resp,
			    &has_data, &has_ent_count, &ent_count);

			/* reset offset, we now start dissecting the data area */
			offset = 0;
			/* data */
			if (d_tvb && tvb_reported_length(d_tvb) > 0) {
				/*
				 * Well, there are bytes that purport to
				 * be data, at least.
				 */
				if (has_data) {
					/*
					 * There's a receive buffer item
					 * in the descriptor string, so
					 * dissect it as response data.
					 */
					dissect_response_data(d_tvb, pinfo,
					    convert, tree, smb_info, lanman,
					    has_ent_count, ent_count);
				} else {
					/*
					 * There's no receive buffer item,
					 * but we do have data, so just
					 * show what bytes are data.
					 */
					proto_tree_add_text(tree, d_tvb, 0, -1,
					    "Data (no receive buffer)");
				}
			}
		}
	}

	return TRUE;
}

void
proto_register_pipe_lanman(void)
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

		{ &hf_aux_data_desc,
			{ "Auxiliary Data Descriptor", "lanman.aux_data_desc", FT_STRING, BASE_NONE,
			NULL, 0, "LANMAN Auxiliary Data Descriptor", HFILL }},

		{ &hf_detail_level,
			{ "Detail Level", "lanman.level", FT_UINT16, BASE_DEC,
			NULL, 0, "LANMAN Detail Level", HFILL }},

		{ &hf_recv_buf_len,
			{ "Receive Buffer Length", "lanman.recv_buf_len", FT_UINT16, BASE_DEC,
			NULL, 0, "LANMAN Receive Buffer Length", HFILL }},

		{ &hf_send_buf_len,
			{ "Send Buffer Length", "lanman.send_buf_len", FT_UINT16, BASE_DEC,
			NULL, 0, "LANMAN Send Buffer Length", HFILL }},

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

		{ &hf_share_path,
			{ "Share Path", "lanman.share.path", FT_STRING, BASE_NONE,
			NULL, 0, "LANMAN Share Path", HFILL }},

		{ &hf_share_password,
			{ "Share Password", "lanman.share.password", FT_STRING, BASE_NONE,
			NULL, 0, "LANMAN Share Password", HFILL }},

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

		{ &hf_enumeration_domain,
			{ "Enumeration Domain", "lanman.enumeration_domain", FT_STRING, BASE_NONE,
			NULL, 0, "LANMAN Domain in which to enumerate servers", HFILL }},

		{ &hf_last_entry,
			{ "Last Entry", "lanman.last_entry", FT_STRING, BASE_NONE,
			NULL, 0, "LANMAN last reported entry of the enumerated servers", HFILL }},

		{ &hf_computer_name,
			{ "Computer Name", "lanman.computer_name", FT_STRING, BASE_NONE,
			NULL, 0, "LANMAN Computer Name", HFILL }},

		{ &hf_user_name,
			{ "User Name", "lanman.user_name", FT_STRING, BASE_NONE,
			NULL, 0, "LANMAN User Name", HFILL }},

		{ &hf_group_name,
			{ "Group Name", "lanman.group_name", FT_STRING, BASE_NONE,
			NULL, 0, "LANMAN Group Name", HFILL }},

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

		{ &hf_comment,
			{ "Comment", "lanman.comment", FT_STRING, BASE_NONE,
			NULL, 0, "LANMAN Comment", HFILL }},

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

		/* XXX - we should have a value_string table for this */
		{ &hf_country_code,
			{ "Country Code", "lanman.country_code", FT_UINT16, BASE_DEC,
			VALS(ms_country_codes), 0, "LANMAN Country Code", HFILL }},

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

		/* XXX - we should have a value_string table for this */
		{ &hf_code_page,
			{ "Code Page", "lanman.code_page", FT_UINT16, BASE_DEC,
			NULL, 0, "LANMAN Code Page", HFILL }},

		{ &hf_new_password,
			{ "New Password", "lanman.new_password", FT_BYTES, BASE_HEX,
			NULL, 0, "LANMAN New Password (encrypted)", HFILL }},

		{ &hf_old_password,
			{ "Old Password", "lanman.old_password", FT_BYTES, BASE_HEX,
			NULL, 0, "LANMAN Old Password (encrypted)", HFILL }},

		{ &hf_reserved,
			{ "Reserved", "lanman.reserved", FT_UINT32, BASE_HEX,
			NULL, 0, "LANMAN Reserved", HFILL }},

	};
	static gint *ett[] = {
		&ett_lanman,
		&ett_lanman_unknown_entries,
		&ett_lanman_unknown_entry,
		&ett_lanman_servers,
		&ett_lanman_server,
		&ett_lanman_groups,
		&ett_lanman_shares,
		&ett_lanman_share,
	};

	proto_smb_lanman = proto_register_protocol(
		"Microsoft Windows Lanman Remote API Protocol", "LANMAN", "lanman");
	proto_register_field_array(proto_smb_lanman, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

static heur_dissector_list_t smb_transact_heur_subdissector_list;

static GHashTable *dcerpc_fragment_table = NULL;
static GHashTable *dcerpc_reassembled_table = NULL;

static void
smb_dcerpc_reassembly_init(void)
{
	fragment_table_init(&dcerpc_fragment_table);
	reassembled_table_init(&dcerpc_reassembled_table);
}

gboolean
dissect_pipe_dcerpc(tvbuff_t *d_tvb, packet_info *pinfo, proto_tree *parent_tree,
    proto_tree *tree, guint32 fid)
{
	smb_info_t *smb_priv = (smb_info_t *)pinfo->private_data;
	gboolean result=0;
	gboolean save_fragmented;
	guint reported_len;
	guint32 hash_key;
	fragment_data *fd_head;
	tvbuff_t *new_tvb;
    proto_item *frag_tree_item;

	pinfo->dcetransportsalt = fid;

	/*
	 * Offer desegmentation service to DCERPC if we have all the
	 * data.  Otherwise, reassembly is (probably) impossible.
	 */
	pinfo->can_desegment=0;
	pinfo->desegment_offset = 0;
	pinfo->desegment_len = 0;
	reported_len = tvb_reported_length(d_tvb);
	if(smb_dcerpc_reassembly && tvb_bytes_exist(d_tvb, 0, reported_len)){
		pinfo->can_desegment=2;
	}

	save_fragmented = pinfo->fragmented;


	/* if we are not offering desegmentation, just try the heuristics
	   and bail out
	*/
	if(!pinfo->can_desegment){
		result = dissector_try_heuristic(smb_transact_heur_subdissector_list, d_tvb, pinfo, parent_tree);
		goto clean_up_and_exit;
	}


	/* below this line, we know we are doing reassembly */
	
	/*
	 * We have to keep track of reassemblies by FID, because
	 * we could have more than one pipe operation in a frame
	 * with NetBIOS-over-TCP.
	 *
	 * We also have to keep track of them by direction, as
	 * we might have reassemblies in progress in both directions.
	 *
	 * We do that by combining the FID and the direction and
	 * using that as the reassembly ID.
	 *
	 * The direction is indicated by the SMB request/reply flag - data
	 * from client to server is carried in requests, data from server
	 * to client is carried in replies.
	 *
	 * We know that the FID is only 16 bits long, so we put the
	 * direction in bit 17.
	 */
	hash_key = fid;
	if (smb_priv->request)
		hash_key |= 0x10000;

	/* this is a new packet, see if we are already reassembling this
	   pdu and if not, check if the dissector wants us
	   to reassemble it
	*/
	if(!pinfo->fd->flags.visited){
		/*
		 * This is the first pass.
		 *
		 * Check if we are already reassembling this PDU or not;
		 * we check for an in-progress reassembly for this FID
		 * in this direction, by searching for its reassembly
		 * structure.
		 */
		fd_head=fragment_get(pinfo, fid, dcerpc_fragment_table);
		if(!fd_head){
			/* No reassembly, so this is a new pdu. check if the
			   dissector wants us to reassemble it or if we
			   already got the full pdu in this tvb.
			*/

			/*
			 * First, just check if it looks like dcerpc or not.
			 *
			 * XXX - this assumes that the dissector is idempotent,
			 * as it's doing a "trial" dissection building no
			 * tree; that's not necessarily the case.
			 */
			result = dissector_try_heuristic(smb_transact_heur_subdissector_list, d_tvb, pinfo, NULL);
			
			/* no this didnt look like something we know */
			if(!result){
				goto clean_up_and_exit;
			}

			/* did the subdissector want us to reassemble any
			   more data ?
			*/
			if(pinfo->desegment_len){
				fragment_add_check(d_tvb, 0, pinfo, fid,
					dcerpc_fragment_table,
					dcerpc_reassembled_table,
					0, reported_len, TRUE);
				fragment_set_tot_len(pinfo, fid,
					dcerpc_fragment_table,
					pinfo->desegment_len+reported_len);
				goto clean_up_and_exit;
			}

			/* guess we have the full pdu in this tvb then,
			   just dissect it and continue.
			*/
			result = dissector_try_heuristic(smb_transact_heur_subdissector_list, d_tvb, pinfo, parent_tree);
			goto clean_up_and_exit;
		}

		/* OK, we're already doing a reassembly for this FID.
		   skip to last segment in the existing reassembly structure
		   and add this fragment there

		   XXX we might add code here to use any offset values
		   we might pick up from the Read/Write calls instead of
		   assuming we always get them in the correct order
		*/
		while(fd_head->next){
			fd_head=fd_head->next;
		}
		fd_head=fragment_add_check(d_tvb, 0, pinfo, fid,
			dcerpc_fragment_table, dcerpc_reassembled_table,
			fd_head->offset+fd_head->len,
			reported_len, TRUE);

		/* if we completed reassembly */
		if(fd_head){
			new_tvb = tvb_new_real_data(fd_head->data,
				  fd_head->datalen, fd_head->datalen);
			tvb_set_child_real_data_tvbuff(d_tvb, new_tvb);
			add_new_data_source(pinfo, new_tvb,
				  "DCERPC over SMB");
			pinfo->fragmented=FALSE;

			d_tvb=new_tvb;

			/* list what segments we have */
			show_fragment_tree(fd_head, &smb_pipe_frag_items,
			    tree, pinfo, d_tvb, &frag_tree_item);

			/* dissect the full PDU */
			result = dissector_try_heuristic(smb_transact_heur_subdissector_list, d_tvb, pinfo, parent_tree);
		}
		goto clean_up_and_exit;
	}

	/*
	 * This is not the first pass; see if it's in the table of
	 * reassembled packets.
	 *
	 * XXX - we know that several of the arguments aren't going to
	 * be used, so we pass bogus variables.  Can we clean this
	 * up so that we don't have to distinguish between the first
	 * pass and subsequent passes?
	 */
	fd_head=fragment_add_check(d_tvb, 0, pinfo, fid, dcerpc_fragment_table,
	    dcerpc_reassembled_table, 0, 0, TRUE);
	if(!fd_head){
		/* we didnt find it, try any of the heuristic dissectors
		   and bail out 
		*/
		result = dissector_try_heuristic(smb_transact_heur_subdissector_list, d_tvb, pinfo, parent_tree);
		goto clean_up_and_exit;
	}
	if(!fd_head->flags&FD_DEFRAGMENTED){
		/* we dont have a fully reassembled frame */
		result = dissector_try_heuristic(smb_transact_heur_subdissector_list, d_tvb, pinfo, parent_tree);
		goto clean_up_and_exit;
	}

	/* it is reassembled but it was reassembled in a different frame */
	if(pinfo->fd->num!=fd_head->reassembled_in){
		proto_tree_add_uint(parent_tree, hf_pipe_reassembled_in, d_tvb, 0, 0, fd_head->reassembled_in);
		goto clean_up_and_exit;
	}


	/* display the reassembled pdu */
	new_tvb = tvb_new_real_data(fd_head->data,
		  fd_head->datalen, fd_head->datalen);
	tvb_set_child_real_data_tvbuff(d_tvb, new_tvb);
	add_new_data_source(pinfo, new_tvb,
		  "DCERPC over SMB");
	pinfo->fragmented=FALSE;

	d_tvb=new_tvb;

	/* list what segments we have */
	show_fragment_tree(fd_head, &smb_pipe_frag_items,
		    tree, pinfo, d_tvb, &frag_tree_item);

	/* dissect the full PDU */
	result = dissector_try_heuristic(smb_transact_heur_subdissector_list, d_tvb, pinfo, parent_tree);
	


clean_up_and_exit:
	/* clear out the variables */
	pinfo->private_data = smb_priv;
	pinfo->can_desegment=0;
	pinfo->desegment_offset = 0;
	pinfo->desegment_len = 0;

	if (!result)
		call_dissector(data_handle, d_tvb, pinfo, parent_tree);

	pinfo->fragmented = save_fragmented;
	return TRUE;
}

void
proto_register_pipe_dcerpc(void)
{
	register_heur_dissector_list("smb_transact", &smb_transact_heur_subdissector_list);
	register_init_routine(smb_dcerpc_reassembly_init);
}

#define CALL_NAMED_PIPE		0x54
#define WAIT_NAMED_PIPE		0x53
#define PEEK_NAMED_PIPE		0x23
#define Q_NM_P_HAND_STATE	0x21
#define SET_NM_P_HAND_STATE	0x01
#define Q_NM_PIPE_INFO		0x22
#define TRANSACT_NM_PIPE	0x26
#define RAW_READ_NM_PIPE	0x11
#define RAW_WRITE_NM_PIPE	0x31

static const value_string functions[] = {
	{CALL_NAMED_PIPE,	"CallNamedPipe"},
	{WAIT_NAMED_PIPE,	"WaitNamedPipe"},
	{PEEK_NAMED_PIPE,	"PeekNamedPipe"},
	{Q_NM_P_HAND_STATE,	"QNmPHandState"},
	{SET_NM_P_HAND_STATE,	"SetNmPHandState"},
	{Q_NM_PIPE_INFO,	"QNmPipeInfo"},
	{TRANSACT_NM_PIPE,	"TransactNmPipe"},
	{RAW_READ_NM_PIPE,	"RawReadNmPipe"},
	{RAW_WRITE_NM_PIPE,	"RawWriteNmPipe"},
	{0,			NULL}
};

static const value_string pipe_status[] = {
	{1,	"Disconnected by server"},
	{2,	"Listening"},
	{3,	"Connection to server is OK"},
	{4,	"Server end of pipe is closed"},
	{0,	NULL}
};

#define PIPE_LANMAN     1
#define PIPE_DCERPC     2

/* decode the SMB pipe protocol
   for requests
    pipe is the name of the pipe, e.g. LANMAN
    smb_info->trans_subcmd is set to the symbolic constant matching the mailslot name
  for responses
    pipe is NULL
    smb_info->trans_subcmd gives us which pipe this response is for
*/
gboolean
dissect_pipe_smb(tvbuff_t *sp_tvb, tvbuff_t *s_tvb, tvbuff_t *pd_tvb,
		 tvbuff_t *p_tvb, tvbuff_t *d_tvb, const char *pipe,
		 packet_info *pinfo, proto_tree *tree)
{
	smb_info_t *smb_info;
	smb_transact_info_t *tri;
	guint sp_len;
	proto_item *pipe_item = NULL;
	proto_tree *pipe_tree = NULL;
	int offset;
	int trans_subcmd=0;
	int function;
	int fid = -1;
	guint16 info_level;

	if (!proto_is_protocol_enabled(find_protocol_by_id(proto_smb_pipe)))
		return FALSE;
	pinfo->current_proto = "SMB Pipe";

	smb_info = pinfo->private_data;

	/*
	 * Set the columns.
	 */
	if (check_col(pinfo->cinfo, COL_PROTOCOL)) {
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "SMB Pipe");
	}
	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_set_str(pinfo->cinfo, COL_INFO,
		    smb_info->request ? "Request" : "Response");
	}

	if (smb_info->sip != NULL && smb_info->sip->extra_info_type == SMB_EI_TRI)
		tri = smb_info->sip->extra_info;
	else
		tri = NULL;

	/*
	 * Set up a subtree for the pipe protocol.  (It might not contain
	 * anything.)
	 */
	if (sp_tvb != NULL)
		sp_len = tvb_length(sp_tvb);
	else
		sp_len = 0;
	if (tree) {
		pipe_item = proto_tree_add_item(tree, proto_smb_pipe,
		    sp_tvb, 0, sp_len, FALSE);
		pipe_tree = proto_item_add_subtree(pipe_item, ett_smb_pipe);
	}
	offset = 0;

	/*
	 * Do we have any setup words at all?
	 */
	if (s_tvb != NULL && tvb_length(s_tvb) != 0) {
		/*
		 * Yes.  The first of them is the function.
		 */
		function = tvb_get_letohs(s_tvb, offset);
		proto_tree_add_uint(pipe_tree, hf_pipe_function, s_tvb,
		    offset, 2, function);
		offset += 2;
		if (check_col(pinfo->cinfo, COL_INFO)) {
			col_add_fstr(pinfo->cinfo, COL_INFO, "%s %s",
			    val_to_str(function, functions, "Unknown function (0x%04x)"),
			    smb_info->request ? "Request" : "Response");
		}
		if (tri != NULL)
			tri->function = function;

		/*
		 * The second of them depends on the function.
		 */
		switch (function) {

		case CALL_NAMED_PIPE:
		case WAIT_NAMED_PIPE:
			/*
			 * It's a priority.
			 */
			proto_tree_add_item(pipe_tree, hf_pipe_priority, s_tvb,
			    offset, 2, TRUE);
			break;

		case PEEK_NAMED_PIPE:
		case Q_NM_P_HAND_STATE:
		case SET_NM_P_HAND_STATE:
		case Q_NM_PIPE_INFO:
		case TRANSACT_NM_PIPE:
		case RAW_READ_NM_PIPE:
		case RAW_WRITE_NM_PIPE:
			/*
			 * It's a FID.
			 */
			fid = tvb_get_letohs(s_tvb, 2);
			add_fid(s_tvb, pinfo, pipe_tree, offset, 2, (guint16) fid);
			if (tri != NULL)
				tri->fid = fid;
			break;

		default:
			/*
			 * It's something unknown.
			 * XXX - put it into the tree?
			 */
			break;
		}
		offset += 2;
	} else {
		/*
		 * This is either a response or a pipe transaction with
		 * no setup information.
		 *
		 * In the former case, we can get that information from
		 * the matching request, if we saw it.
		 *
		 * In the latter case, there is no function or FID.
		 */
		if (tri != NULL && tri->function != -1) {
			function = tri->function;
			proto_tree_add_uint(pipe_tree, hf_pipe_function, NULL,
			    0, 0, function);
			if (check_col(pinfo->cinfo, COL_INFO)) {
				col_add_fstr(pinfo->cinfo, COL_INFO, "%s %s",
				    val_to_str(function, functions, "Unknown function (0x%04x)"),
				    smb_info->request ? "Request" : "Response");
			}
			fid = tri->fid;
			if (fid != -1)
				add_fid(NULL, pinfo, pipe_tree, 0, 0, (guint16) fid);
		} else {
			function = -1;
			fid = -1;
		}
	}

	/*
	 * XXX - put the byte count and the pipe name into the tree as well;
	 * that requires us to fetch a possibly-Unicode string.
	 */

	if(smb_info->request){
		if(strncmp(pipe,"LANMAN",6) == 0){
			trans_subcmd=PIPE_LANMAN;
		} else {
			/* assume it is DCERPC */
			trans_subcmd=PIPE_DCERPC;
		}

		if (!pinfo->fd->flags.visited)
			tri->trans_subcmd = trans_subcmd;
	} else {
		if(tri){
			trans_subcmd = tri->trans_subcmd;
		} else {
			return FALSE;
		}
        }

	if (tri == NULL) {
		/*
		 * We don't know what type of pipe transaction this
		 * was, so indicate that we didn't dissect it.
		 */
		return FALSE;
	}

	switch (function) {

	case CALL_NAMED_PIPE:
	case TRANSACT_NM_PIPE:
		switch(trans_subcmd){

		case PIPE_LANMAN:
			return dissect_pipe_lanman(pd_tvb, p_tvb, d_tvb, pinfo,
			    tree);
			break;

		case PIPE_DCERPC:
			/*
			 * Only dissect this if we know the FID.
			 */
			if (fid != -1) {
				if (d_tvb == NULL)
					return FALSE;
		                return dissect_pipe_dcerpc(d_tvb, pinfo, tree,
		                    pipe_tree, fid);
		        }
			break;
		}
		break;

	case -1:
		/*
		 * We don't know the function; we dissect only LANMAN
		 * pipe messages, not RPC pipe messages, in that case.
		 */
		switch(trans_subcmd){
		case PIPE_LANMAN:
			return dissect_pipe_lanman(pd_tvb, p_tvb, d_tvb, pinfo,
			    tree);
			break;
		}
		break;

	case WAIT_NAMED_PIPE:
		break;

	case PEEK_NAMED_PIPE:
		/*
		 * Request contains no parameters or data.
		 */
		if (!smb_info->request) {
			if (p_tvb == NULL)
				return FALSE;
			offset = 0;
			proto_tree_add_item(pipe_tree, hf_pipe_peek_available,
			    p_tvb, offset, 2, TRUE);
			offset += 2;
			proto_tree_add_item(pipe_tree, hf_pipe_peek_remaining,
			    p_tvb, offset, 2, TRUE);
			offset += 2;
			proto_tree_add_item(pipe_tree, hf_pipe_peek_status,
			    p_tvb, offset, 2, TRUE);
			offset += 2;
		}
		break;

	case Q_NM_P_HAND_STATE:
		/*
		 * Request contains no parameters or data.
		 */
		if (!smb_info->request) {
			if (p_tvb == NULL)
				return FALSE;
			offset = dissect_ipc_state(p_tvb, pipe_tree, 0, FALSE);
		}
		break;

	case SET_NM_P_HAND_STATE:
		/*
		 * Response contains no parameters or data.
		 */
		if (smb_info->request) {
			if (p_tvb == NULL)
				return FALSE;
			offset = dissect_ipc_state(p_tvb, pipe_tree, 0, TRUE);
		}
		break;

	case Q_NM_PIPE_INFO:
		offset = 0;
		if (smb_info->request) {
			if (p_tvb == NULL)
				return FALSE;

			/*
			 * Request contains an information level.
			 */
			info_level = tvb_get_letohs(p_tvb, offset);
			proto_tree_add_uint(pipe_tree, hf_pipe_getinfo_info_level,
			    p_tvb, offset, 2, info_level);
			offset += 2;
			if (!pinfo->fd->flags.visited)
				tri->info_level = info_level;
		} else {
			guint8 pipe_namelen;

			if (d_tvb == NULL)
				return FALSE;

			switch (tri->info_level) {

			case 1:
				proto_tree_add_item(pipe_tree,
				    hf_pipe_getinfo_output_buffer_size,
				    d_tvb, offset, 2, TRUE);
				offset += 2;
				proto_tree_add_item(pipe_tree,
				    hf_pipe_getinfo_input_buffer_size,
				    d_tvb, offset, 2, TRUE);
				offset += 2;
				proto_tree_add_item(pipe_tree,
				    hf_pipe_getinfo_maximum_instances,
				    d_tvb, offset, 1, TRUE);
				offset += 1;
				proto_tree_add_item(pipe_tree,
				    hf_pipe_getinfo_current_instances,
				    d_tvb, offset, 1, TRUE);
				offset += 1;
				pipe_namelen = tvb_get_guint8(d_tvb, offset);
				proto_tree_add_uint(pipe_tree,
				    hf_pipe_getinfo_pipe_name_length,
				    d_tvb, offset, 1, pipe_namelen);
				offset += 1;
				/* XXX - can this be Unicode? */
				proto_tree_add_item(pipe_tree,
				    hf_pipe_getinfo_pipe_name,
				    d_tvb, offset, pipe_namelen, TRUE);
				break;
			}
		}
		break;

	case RAW_READ_NM_PIPE:
		/*
		 * Request contains no parameters or data.
		 */
		if (!smb_info->request) {
			if (d_tvb == NULL)
				return FALSE;

			offset = dissect_file_data(d_tvb, pipe_tree, 0,
			    (guint16) tvb_reported_length(d_tvb),
			    (guint16) tvb_reported_length(d_tvb));
		}
		break;

	case RAW_WRITE_NM_PIPE:
		offset = 0;
		if (smb_info->request) {
			if (d_tvb == NULL)
				return FALSE;

			offset = dissect_file_data(d_tvb, pipe_tree,
			    offset, (guint16) tvb_reported_length(d_tvb),
			    (guint16) tvb_reported_length(d_tvb));
		} else {
			if (p_tvb == NULL)
				return FALSE;
			proto_tree_add_item(pipe_tree,
			    hf_pipe_write_raw_bytes_written,
			    p_tvb, offset, 2, TRUE);
			offset += 2;
		}
		break;
	}
	return TRUE;
}

void
proto_register_smb_pipe(void)
{
	static hf_register_info hf[] = {
		{ &hf_pipe_function,
			{ "Function", "pipe.function", FT_UINT16, BASE_HEX,
			VALS(functions), 0, "SMB Pipe Function Code", HFILL }},
		{ &hf_pipe_priority,
			{ "Priority", "pipe.priority", FT_UINT16, BASE_DEC,
			NULL, 0, "SMB Pipe Priority", HFILL }},
		{ &hf_pipe_peek_available,
			{ "Available Bytes", "pipe.peek.available_bytes", FT_UINT16, BASE_DEC,
			NULL, 0, "Total number of bytes available to be read from the pipe", HFILL }},
		{ &hf_pipe_peek_remaining,
			{ "Bytes Remaining", "pipe.peek.remaining_bytes", FT_UINT16, BASE_DEC,
			NULL, 0, "Total number of bytes remaining in the message at the head of the pipe", HFILL }},
		{ &hf_pipe_peek_status,
			{ "Pipe Status", "pipe.peek.status", FT_UINT16, BASE_DEC,
			VALS(pipe_status), 0, "Pipe status", HFILL }},
		{ &hf_pipe_getinfo_info_level,
			{ "Information Level", "pipe.getinfo.info_level", FT_UINT16, BASE_DEC,
			NULL, 0, "Information level of information to return", HFILL }},
		{ &hf_pipe_getinfo_output_buffer_size,
			{ "Output Buffer Size", "pipe.getinfo.output_buffer_size", FT_UINT16, BASE_DEC,
			NULL, 0, "Actual size of buffer for outgoing (server) I/O", HFILL }},
		{ &hf_pipe_getinfo_input_buffer_size,
			{ "Input Buffer Size", "pipe.getinfo.input_buffer_size", FT_UINT16, BASE_DEC,
			NULL, 0, "Actual size of buffer for incoming (client) I/O", HFILL }},
		{ &hf_pipe_getinfo_maximum_instances,
			{ "Maximum Instances", "pipe.getinfo.maximum_instances", FT_UINT8, BASE_DEC,
			NULL, 0, "Maximum allowed number of instances", HFILL }},
		{ &hf_pipe_getinfo_current_instances,
			{ "Current Instances", "pipe.getinfo.current_instances", FT_UINT8, BASE_DEC,
			NULL, 0, "Current number of instances", HFILL }},
		{ &hf_pipe_getinfo_pipe_name_length,
			{ "Pipe Name Length", "pipe.getinfo.pipe_name_length", FT_UINT8, BASE_DEC,
			NULL, 0, "Length of pipe name", HFILL }},
		{ &hf_pipe_getinfo_pipe_name,
			{ "Pipe Name", "pipe.getinfo.pipe_name", FT_STRING, BASE_NONE,
			NULL, 0, "Name of pipe", HFILL }},
		{ &hf_pipe_write_raw_bytes_written,
			{ "Bytes Written", "pipe.write_raw.bytes_written", FT_UINT16, BASE_DEC,
			NULL, 0, "Number of bytes written to the pipe", HFILL }},
		{ &hf_pipe_fragment_overlap,
			{ "Fragment overlap",	"pipe.fragment.overlap", FT_BOOLEAN, BASE_NONE,
			NULL, 0x0, "Fragment overlaps with other fragments", HFILL }},
		{ &hf_pipe_fragment_overlap_conflict,
			{ "Conflicting data in fragment overlap",	"pipe.fragment.overlap.conflict", FT_BOOLEAN,
			BASE_NONE, NULL, 0x0, "Overlapping fragments contained conflicting data", HFILL }},
		{ &hf_pipe_fragment_multiple_tails,
			{ "Multiple tail fragments found",	"pipe.fragment.multipletails", FT_BOOLEAN,
			BASE_NONE, NULL, 0x0, "Several tails were found when defragmenting the packet", HFILL }},
		{ &hf_pipe_fragment_too_long_fragment,
			{ "Fragment too long",	"pipe.fragment.toolongfragment", FT_BOOLEAN,
			BASE_NONE, NULL, 0x0, "Fragment contained data past end of packet", HFILL }},
		{ &hf_pipe_fragment_error,
			{ "Defragmentation error", "pipe.fragment.error", FT_FRAMENUM,
			BASE_NONE, NULL, 0x0, "Defragmentation error due to illegal fragments", HFILL }},
		{ &hf_pipe_fragment,
			{ "Fragment", "pipe.fragment", FT_FRAMENUM,
			BASE_NONE, NULL, 0x0, "Pipe Fragment", HFILL }},
		{ &hf_pipe_fragments,
			{ "Fragments", "pipe.fragments", FT_NONE,
			BASE_NONE, NULL, 0x0, "Pipe Fragments", HFILL }},
		{ &hf_pipe_reassembled_in,
			{ "This PDU is reassembled in", "pipe.reassembled_in", FT_FRAMENUM,
			BASE_NONE, NULL, 0x0, "The DCE/RPC PDU is completely reassembled in this frame", HFILL }},
	};
	static gint *ett[] = {
		&ett_smb_pipe,
		&ett_smb_pipe_fragment,
		&ett_smb_pipe_fragments,
	};

	proto_smb_pipe = proto_register_protocol(
		"SMB Pipe Protocol", "SMB Pipe", "pipe");

	proto_register_field_array(proto_smb_pipe, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_smb_pipe(void)
{
	data_handle = find_dissector("data");
}
