/*
XXX  Fixme : shouldnt show [malformed frame] for long packets
*/

/* packet-smb-pipe.c
 * Routines for SMB named pipe packet dissection
 * Copyright 1999, Richard Sharpe <rsharpe@ns.aus.com>
 * significant rewrite to tvbuffify the dissector, Ronnie Sahlberg and
 * Guy Harris 2001
 *
 * $Id: packet-smb-pipe.c,v 1.38 2001/11/03 00:58:49 guy Exp $
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
static int hf_aux_data_desc = -1;
static int hf_detail_level = -1;
static int hf_recv_buf_len = -1;
static int hf_send_buf_len = -1;
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
static int hf_reserved = -1;

static gint ett_lanman = -1;
static gint ett_lanman_shares = -1;
static gint ett_lanman_share = -1;
static gint ett_lanman_servers = -1;
static gint ett_lanman_server = -1;

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
add_word_param(tvbuff_t *tvb, int offset, int count, packet_info *pinfo,
    proto_tree *tree, int convert, int hf_index)
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
add_dword_param(tvbuff_t *tvb, int offset, int count, packet_info *pinfo,
    proto_tree *tree, int convert, int hf_index)
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
add_byte_param(tvbuff_t *tvb, int offset, int count, packet_info *pinfo,
    proto_tree *tree, int convert, int hf_index)
{
	guint8 BParam;

	if (hf_index != -1)
		proto_tree_add_item(tree, hf_index, tvb, offset, count, TRUE);
	else {
		if (count == 1) {
			BParam = tvb_get_guint8(tvb, offset);
			proto_tree_add_text(tree, tvb, offset, count,
			    "Byte Param: %u (0x%02X)",
			    BParam, BParam);
		} else {
			proto_tree_add_text(tree, tvb, offset, count,
			    "Bytes Param: %s, type is wrong",
			    tvb_bytes_to_str(tvb, offset, count));
		}
	}
	offset += count;
	return offset;
}

static int
add_pad_param(tvbuff_t *tvb, int offset, int count, packet_info *pinfo,
    proto_tree *tree, int convert, int hf_index)
{
	/*
	 * This is for parameters that have descriptor entries but that
	 * are, in practice, just padding.
	 */
	offset += count;
	return offset;
}

static void
add_null_pointer_param(tvbuff_t *tvb, int offset, int count,
    packet_info *pinfo, proto_tree *tree, int convert, int hf_index)
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
add_string_param(tvbuff_t *tvb, int offset, int count, packet_info *pinfo,
    proto_tree *tree, int convert, int hf_index)
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
get_pointer_value(tvbuff_t *tvb, int offset, int convert, int *cptrp, int *lenp)
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
add_pointer_param(tvbuff_t *tvb, int offset, int count, packet_info *pinfo,
    proto_tree *tree, int convert, int hf_index)
{
	int cptr;
	const char *string;
	gint string_len;

	string = get_pointer_value(tvb, offset, convert, &cptr, &string_len);
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
add_detail_level(tvbuff_t *tvb, int offset, int count, packet_info *pinfo,
    proto_tree *tree, int convert, int hf_index)
{
	struct smb_info *smb_info = pinfo->private_data;
	struct smb_request_val *request_val = smb_info->request_val;
	guint16 level;

	level = tvb_get_letohs(tvb, offset);
	if (!pinfo->fd->flags.visited)
		request_val->last_level = level;	/* remember this for the response */
	proto_tree_add_uint(tree, hf_index, tvb, offset, 2, level);
	offset += 2;
	return offset;
}

static int
add_max_uses(tvbuff_t *tvb, int offset, int count, packet_info *pinfo,
    proto_tree *tree, int convert, int hf_index)
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
add_server_type(tvbuff_t *tvb, int offset, int count,
    packet_info *pinfo, proto_tree *tree, int convert, int hf_index)
{
	dissect_smb_server_type_flags(tvb, pinfo, tree, offset, FALSE);
	offset += 4;
	return offset;
}

static int
add_server_type_info(tvbuff_t *tvb, int offset, int count,
    packet_info *pinfo, proto_tree *tree, int convert, int hf_index)
{
	dissect_smb_server_type_flags(tvb, pinfo, tree, offset, TRUE);
	offset += 4;
	return offset;
}

static int
add_reltime(tvbuff_t *tvb, int offset, int count, packet_info *pinfo,
    proto_tree *tree, int convert, int hf_index)
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
add_abstime_common(tvbuff_t *tvb, int offset, int count,
    packet_info *pinfo, proto_tree *tree, int convert, int hf_index,
    const char *absent_name)
{
	nstime_t nstime;
	struct tm *tmp;

	nstime.secs = tvb_get_letohl(tvb, offset);
	nstime.nsecs = 0;
	if (nstime.secs == -1) {
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
add_abstime_absent_never(tvbuff_t *tvb, int offset, int count,
    packet_info *pinfo, proto_tree *tree, int convert, int hf_index)
{
	return add_abstime_common(tvb, offset, count, pinfo, tree,
	    convert, hf_index, "Never");
}

static int
add_abstime_absent_unknown(tvbuff_t *tvb, int offset, int count,
    packet_info *pinfo, proto_tree *tree, int convert, int hf_index)
{
	return add_abstime_common(tvb, offset, count, pinfo, tree,
	    convert, hf_index, "Unknown");
}

static int
add_nlogons(tvbuff_t *tvb, int offset, int count, packet_info *pinfo,
    proto_tree *tree, int convert, int hf_index)
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
add_max_storage(tvbuff_t *tvb, int offset, int count, packet_info *pinfo,
    proto_tree *tree, int convert, int hf_index)
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
add_logon_hours(tvbuff_t *tvb, int offset, int count, packet_info *pinfo,
    proto_tree *tree, int convert, int hf_index)
{
	int cptr;

	/* pointer to string */
	cptr = (tvb_get_letohl(tvb, offset)&0xffff)-convert;
	offset += 4;

	/* string */
	/* XXX - should actually carve up the bits */
	proto_tree_add_item(tree, hf_index, tvb, cptr, 21, TRUE);

	return offset;
}

static int
add_tzoffset(tvbuff_t *tvb, int offset, int count, packet_info *pinfo,
    proto_tree *tree, int convert, int hf_index)
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
add_timeinterval(tvbuff_t *tvb, int offset, int count, packet_info *pinfo,
    proto_tree *tree, int convert, int hf_index)
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
add_logon_args(tvbuff_t *tvb, int offset, int count, packet_info *pinfo,
    proto_tree *tree, int convert, int hf_index)
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
	PARAM_STRINGZ,	/* 'z' or 'O' - null-terminated string */
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
	proto_item	*(*resp_data_item)(tvbuff_t *, packet_info *,
					   proto_tree *, int);
	gint		*ett_resp_data;
	proto_item	*(*resp_data_element_item)(tvbuff_t *, packet_info *,
						   proto_tree *, int);
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
 * Create a subtree for all available shares.
 */
static proto_item *
netshareenum_shares_list(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    int offset)
{
	if (tree) {
		return proto_tree_add_text(tree, tvb, offset,
		    tvb_length_remaining(tvb, offset),
		    "Available Shares");
	} else
		return NULL;
}

/*
 * Create a subtree for a share.
 */
static proto_item *
netshareenum_share_entry(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    int offset)
{
	if (tree) {
		return proto_tree_add_text(tree, tvb, offset,
		    tvb_length_remaining(tvb, offset),
		    "Share %.13s", tvb_get_ptr(tvb, offset, 13));
	} else
		return NULL;
}

static const item_t lm_null[] = {
	{ NULL, NULL, PARAM_NONE }
};

static const item_list_t lm_null_list[] = {
	{ 0, lm_null }
};

static const item_t lm_data_resp_netshareenum_1[] = {
	{ &hf_share_name, add_byte_param, PARAM_BYTES },
	{ &no_hf, add_pad_param, PARAM_BYTES },
	{ &hf_share_type, add_word_param, PARAM_WORD },
	{ &hf_share_comment, add_pointer_param, PARAM_STRINGZ },
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
	{ &hf_share_comment, add_pointer_param, PARAM_STRINGZ },
	{ NULL, NULL, PARAM_NONE }
};

static const item_t lm_data_resp_netsharegetinfo_2[] = {
	{ &hf_share_name, add_byte_param, PARAM_BYTES },
	{ &no_hf, add_pad_param, PARAM_BYTES },
	{ &hf_share_type, add_word_param, PARAM_WORD },
	{ &hf_share_comment, add_pointer_param, PARAM_STRINGZ },
	{ &hf_share_permissions, add_word_param, PARAM_WORD }, /* XXX - do as bit fields */
	{ &hf_share_max_uses, add_max_uses, PARAM_WORD },
	{ &hf_share_current_uses, add_word_param, PARAM_WORD },
	{ &hf_share_path, add_pointer_param, PARAM_STRINGZ },
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
	{ &hf_server_comment, add_pointer_param, PARAM_STRINGZ },
	{ NULL, NULL, PARAM_NONE }
};

static const item_list_t lm_data_serverinfo[] = {
	{ 0, lm_data_serverinfo_0 },
	{ 1, lm_data_serverinfo_1 },
	{ -1, lm_null }
};

static const item_t lm_params_req_netusergetinfo[] = {
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
	{ &hf_user_comment, add_pointer_param, PARAM_STRINGZ },
	{ &hf_full_name, add_pointer_param, PARAM_STRINGZ },
	{ &hf_privilege_level, add_word_param, PARAM_WORD },
	{ &hf_operator_privileges, add_dword_param, PARAM_DWORD },
	{ &hf_password_age, add_reltime, PARAM_DWORD },
	{ &hf_homedir, add_pointer_param, PARAM_STRINGZ },
	{ &hf_parameters, add_pointer_param, PARAM_STRINGZ },
	{ &hf_last_logon, add_abstime_absent_unknown, PARAM_DWORD },
	{ &hf_last_logoff, add_abstime_absent_unknown, PARAM_DWORD },
	{ &hf_bad_pw_count, add_word_param, PARAM_WORD },
	{ &hf_num_logons, add_nlogons, PARAM_WORD },
	{ &hf_logon_server, add_pointer_param, PARAM_STRINGZ },
	{ &hf_country_code, add_word_param, PARAM_WORD },
	{ &hf_workstations, add_pointer_param, PARAM_STRINGZ },
	{ &hf_max_storage, add_max_storage, PARAM_DWORD },
	{ &hf_logon_hours, add_logon_hours, PARAM_DWORD },
	{ &hf_code_page, add_word_param, PARAM_WORD },
	{ NULL, NULL, PARAM_NONE }
};

static const item_list_t lm_data_resp_netusergetinfo[] = {
	{ 11, lm_data_resp_netusergetinfo_11 },
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
 * Create a subtree for all servers.
 */
static proto_item *
netserverenum2_servers_list(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    int offset)
{
	if (tree) {
		return proto_tree_add_text(tree, tvb, offset,
		    tvb_length_remaining(tvb, offset), "Servers");
	} else
		return NULL;
}

/*
 * Create a subtree for a share.
 */
static proto_item *
netserverenum2_server_entry(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    int offset)
{
	if (tree) {
		return proto_tree_add_text(tree, tvb, offset,
			    tvb_length_remaining(tvb, offset),
			    "Server %.16s", tvb_get_ptr(tvb, offset, 16));
	} else
		return NULL;
}
static const item_t lm_params_resp_netserverenum2[] = {
	{ &hf_acount, add_word_param, PARAM_WORD },
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
	{ &hf_computer_name, add_pointer_param, PARAM_STRINGZ },
	{ &hf_user_name, add_pointer_param, PARAM_STRINGZ },
	{ &hf_workstation_domain, add_pointer_param, PARAM_STRINGZ },
	{ &hf_workstation_major, add_byte_param, PARAM_BYTES },
	{ &hf_workstation_minor, add_byte_param, PARAM_BYTES },
	{ &hf_logon_domain, add_pointer_param, PARAM_STRINGZ },
	{ &hf_other_domains, add_pointer_param, PARAM_STRINGZ },
	{ NULL, NULL, PARAM_NONE }
};

static const item_list_t lm_data_resp_netwkstagetinfo[] = {
	{ 10, lm_data_resp_netwkstagetinfo_10 },
	{ -1, lm_null }
};

static const item_t lm_params_req_netwkstauserlogon[] = {
	{ &no_hf, add_pointer_param, PARAM_STRINGZ },
	{ &no_hf, add_pointer_param, PARAM_STRINGZ },
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
	{ &hf_server_name, add_pointer_param, PARAM_STRINGZ },
	{ &hf_logon_domain, add_pointer_param, PARAM_STRINGZ },
	{ &hf_script_path, add_pointer_param, PARAM_STRINGZ },
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

static const struct lanman_desc lmd[] = {
	{ LANMAN_NETSHAREENUM,
	  lm_params_req_netshareenum,
	  NULL,
	  NULL,
	  lm_null,
	  lm_null,
	  lm_params_resp_netshareenum,
	  netshareenum_shares_list,
	  &ett_lanman_shares,
	  netshareenum_share_entry,
	  &ett_lanman_share,
	  lm_data_resp_netshareenum,
	  lm_null },

	{ LANMAN_NETSHAREGETINFO,
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

	{ LANMAN_NETSERVERGETINFO, 
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

	{ LANMAN_NETUSERGETINFO,
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

	{ LANMAN_NETREMOTETOD,
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

	{ LANMAN_NETSERVERENUM2,
	  lm_params_req_netserverenum2,
	  NULL,
	  NULL,
	  lm_null,
	  lm_null,
	  lm_params_resp_netserverenum2,
	  netserverenum2_servers_list,
	  &ett_lanman_servers,
	  netserverenum2_server_entry,
	  &ett_lanman_server,
	  lm_data_serverinfo,
	  lm_null },

	{ LANMAN_NETWKSTAGETINFO,
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

	{ LANMAN_NETWKSTAUSERLOGON,
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

	{ LANMAN_NETWKSTAUSERLOGOFF,
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

	{ LANMAN_SAMOEMCHANGEPASSWORD,
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
	  NULL,
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
	int count = 0, off = 0;
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
			 * XXX - is there actually a pointer here?
			 * I suspect not.  It looks like junk.
			 */
			*has_data_p = TRUE;
			LParam = tvb_get_letohl(tvb, offset);
			proto_tree_add_text(tree, tvb, offset, 4,
			    "%s: %u", "Send Buffer Ptr", LParam);
			offset += 4;
			break;

		case 'T':
			/*
			 * 16-bit send buffer length.
			 */
			proto_tree_add_item(tree, hf_send_buf_len, tvb,
			    offset, 2, FALSE);
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
				offset = add_pointer_param(tvb, offset, 0,
				    pinfo, tree, convert, -1);
			} else if (items->type != PARAM_STRINGZ) {
				/*
				 * Descriptor character is 'z', but this
				 * isn't a string parameter.
				 */
				string = get_pointer_value(tvb, offset,
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

static void
dissect_response_data(tvbuff_t *tvb, packet_info *pinfo, int convert,
    proto_tree *tree, struct smb_info *smb_info,
    const struct lanman_desc *lanman, gboolean has_ent_count,
    guint16 ent_count)
{
	struct smb_request_val *request_val = smb_info->request_val;
	const item_list_t *resp_data_list;
	int offset, start_offset;
	const item_t *resp_data;
	proto_item *data_item;
	proto_tree *data_tree;
	proto_item *entry_item;
	proto_tree *entry_tree;
	guint i, j;
	guint16 aux_count;

	/*
	 * Find the item table for the matching request's detail level.
	 */
	for (resp_data_list = lanman->resp_data_list;
	    resp_data_list->level != -1; resp_data_list++) {
		if (resp_data_list->level == request_val->last_level)
			break;
	}
	resp_data = resp_data_list->item_list;

	offset = smb_info->data_offset;
	if (lanman->resp_data_item != NULL) {
		/*
		 * Create a protocol tree item for the data.
		 */
		data_item = (*lanman->resp_data_item)(tvb,
		    pinfo, tree, offset);
		data_tree = proto_item_add_subtree(data_item,
		    *lanman->ett_resp_data);
	} else {
		/*
		 * Just leave it at the top level.
		 */
		data_item = NULL;
		data_tree = tree;
	}

	if (request_val->last_data_descrip == NULL) {
		/*
		 * This could happen if we only dissected
		 * part of the request to which this is a
		 * reply, e.g. if the request was split
		 * across TCP segments and we weren't doing
		 * TCP desegmentation, or if we had a snapshot
		 * length that was too short.
		 *
		 * We can't dissect the data; just show it
		 * as raw data.
		 */
		proto_tree_add_text(tree, tvb, offset,
		    tvb_length_remaining(tvb, offset),
		    "Data (no descriptor available)");
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
			if (has_ent_count) {
				/*
				 * Create a protocol tree item for the
				 * entry.
				 */
				entry_item =
				    (*lanman->resp_data_element_item)
				      (tvb, pinfo, data_tree, offset);
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
			    request_val->last_data_descrip,
			    resp_data, &aux_count);

			/* auxiliary data */
			if (request_val->last_aux_data_descrip != NULL) {
				for (j = 0; j < aux_count; j++) {
					offset = dissect_transact_data(
					    tvb, offset, convert,
					    pinfo, entry_tree,
					    request_val->last_data_descrip,
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
		proto_item_set_len(data_item,
		    offset - smb_info->data_offset);
	}
}

static gboolean
dissect_pipe_lanman(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	struct smb_info *smb_info = pinfo->private_data;
	struct smb_request_val *request_val = smb_info->request_val;
	int parameter_count = smb_info->parameter_count;
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
	guint i, j;
	proto_item *data_item;
	proto_tree *data_tree;
	proto_item *entry_item;
	proto_tree *entry_tree;

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
		parameter_count -= 2;

		/*
		 * If we haven't already done so, save the function code in
		 * the structure we were handed, so that it's available to
		 * the code parsing the reply, and initialize the detail
		 * level to -1, meaning "unknown".
		 */
		if (!pinfo->fd->flags.visited) {
			request_val->last_lanman_cmd = cmd;
			request_val->last_level = -1;
		}

		/* parameter descriptor */
		descriptor_len = tvb_strsize(tvb, offset);
		proto_tree_add_item(tree, hf_param_desc, tvb, offset,
		    descriptor_len, TRUE);
		param_descrip = tvb_get_ptr(tvb, offset, descriptor_len);
		if (!pinfo->fd->flags.visited) {
			/*
			 * Save the parameter descriptor for future use.
			 */
			g_assert(request_val->last_param_descrip == NULL);
			request_val->last_param_descrip = g_strdup(param_descrip);
		}
		offset += descriptor_len;
		parameter_count -= descriptor_len;

		/* return descriptor */
		descriptor_len = tvb_strsize(tvb, offset);
		proto_tree_add_item(tree, hf_return_desc, tvb, offset,
		    descriptor_len, TRUE);
		data_descrip = tvb_get_ptr(tvb, offset, descriptor_len);
		if (!pinfo->fd->flags.visited) {
			/*
			 * Save the return descriptor for future use.
			 */
			g_assert(request_val->last_data_descrip == NULL);
			request_val->last_data_descrip = g_strdup(data_descrip);
		}
		offset += descriptor_len;
		parameter_count -= descriptor_len;

		lanman = find_lanman(cmd);

		/* request parameters */
		start_offset = offset;
		offset = dissect_request_parameters(tvb, offset, pinfo, tree,
		    param_descrip, lanman->req, &has_data);
		parameter_count -= offset - start_offset;

		/* auxiliary data descriptor */
		if (parameter_count > 0) {
			/*
			 * There are more parameters left, so the next
			 * item is the auxiliary data descriptor.
			 */
			descriptor_len = tvb_strsize(tvb, offset);
			proto_tree_add_item(tree, hf_return_desc, tvb, offset,
			    descriptor_len, TRUE);
			aux_data_descrip = tvb_get_ptr(tvb, offset, descriptor_len);
			if (!pinfo->fd->flags.visited) {
				/*
				 * Save the auxiliary data descriptor for
				 * future use.
				 */
				g_assert(request_val->last_aux_data_descrip == NULL);
				request_val->last_aux_data_descrip =
				    g_strdup(aux_data_descrip);
			}
			offset += descriptor_len;
		}

		if (has_data && smb_info->data_count != 0) {
			/*
			 * There's a send buffer item in the descriptor
			 * string, and the data count in the transaction
			 * is non-zero, so there's data to dissect.
			 *
			 * XXX - should we just check "smb_info->data_count"?
			 */

			offset = smb_info->data_offset;
			if (lanman->req_data_item != NULL) {
				/*
				 * Create a protocol tree item for the data.
				 */
				data_item = (*lanman->req_data_item)(tvb,
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
			offset = dissect_transact_data(tvb, offset, -1,
			    pinfo, data_tree, data_descrip, lanman->req_data,
			    &aux_count);	/* XXX - what about strings? */

			/* auxiliary data */
			if (aux_data_descrip != NULL) {
				for (i = 0; i < aux_count; i++) {
					offset = dissect_transact_data(tvb,
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
				proto_item_set_len(data_item,
				    offset - smb_info->data_offset);
			}
		}
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

		lanman = find_lanman(request_val->last_lanman_cmd);

		/* response parameters */

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

		/* rest of the parameters */
		offset = dissect_response_parameters(tvb, offset, pinfo, tree,
		    request_val->last_param_descrip, lanman->resp, &has_data,
		    &has_ent_count, &ent_count);

		/* data */
		if (has_data && smb_info->data_count != 0) {
			/*
			 * There's a receive buffer item in the descriptor
			 * string, and the data count in the transaction
			 * is non-zero, so there's data to dissect.
			 *
			 * XXX - should we just check "smb_info->data_count"?
			 */
			dissect_response_data(tvb, pinfo, convert, tree,
			    smb_info, lanman, has_ent_count, ent_count);
		}
	}

	return TRUE;
}

gboolean
dissect_pipe_smb(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	struct smb_info *smb_info = pinfo->private_data;

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

		/* XXX - we should have a value_string table for this */
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
