/* packet-smb.c
 * Routines for smb packet dissection
 * Copyright 1999, Richard Sharpe <rsharpe@ns.aus.com>
 *
 * $Id: packet-smb.c,v 1.130 2001/11/05 01:44:17 guy Exp $
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
#include "alignment.h"
#include "strutil.h"

#include "packet-smb-mailslot.h"
#include "packet-smb-pipe.h"

static int proto_smb = -1;
static int hf_smb_cmd = -1;
static int hf_smb_pid = -1;
static int hf_smb_tid = -1;
static int hf_smb_uid = -1;
static int hf_smb_mid = -1;
static int hf_smb_response_to = -1;
static int hf_smb_response_in = -1;
static int hf_smb_nt_status = -1;
static int hf_smb_error_class = -1;
static int hf_smb_error_code = -1;
static int hf_smb_reserved = -1;
static int hf_smb_flags_lock = -1;
static int hf_smb_flags_receive_buffer = -1;
static int hf_smb_flags_caseless = -1;
static int hf_smb_flags_canon = -1;
static int hf_smb_flags_oplock = -1;
static int hf_smb_flags_notify = -1;
static int hf_smb_flags_response = -1;
static int hf_smb_flags2_long_names_allowed = -1;
static int hf_smb_flags2_ea = -1;
static int hf_smb_flags2_sec_sig = -1;
static int hf_smb_flags2_long_names_used = -1;
static int hf_smb_flags2_esn = -1;
static int hf_smb_flags2_dfs = -1;
static int hf_smb_flags2_roe = -1;
static int hf_smb_flags2_nt_error = -1;
static int hf_smb_flags2_string = -1;
static int hf_smb_word_count = -1;
static int hf_smb_byte_count = -1;
static int hf_smb_buffer_format = -1;
static int hf_smb_dialect_name = -1;
static int hf_smb_dialect_index = -1;
static int hf_smb_max_trans_buf_size = -1;
static int hf_smb_max_mpx_count = -1;
static int hf_smb_max_vcs_num = -1;
static int hf_smb_session_key = -1;
static int hf_smb_server_timezone = -1;
static int hf_smb_encryption_key_length = -1;
static int hf_smb_encryption_key = -1;
static int hf_smb_primary_domain = -1;
static int hf_smb_max_raw_buf_size = -1;
static int hf_smb_server_guid = -1;
static int hf_smb_security_blob = -1;
static int hf_smb_sm_mode16 = -1;
static int hf_smb_sm_password16 = -1;
static int hf_smb_sm_mode = -1;
static int hf_smb_sm_password = -1;
static int hf_smb_sm_signatures = -1;
static int hf_smb_sm_sig_required = -1;
static int hf_smb_rm_read = -1;
static int hf_smb_rm_write = -1;
static int hf_smb_server_date_time = -1;
static int hf_smb_server_smb_date = -1;
static int hf_smb_server_smb_time = -1;
static int hf_smb_server_cap_raw_mode = -1;
static int hf_smb_server_cap_mpx_mode = -1;
static int hf_smb_server_cap_unicode = -1;
static int hf_smb_server_cap_large_files = -1;
static int hf_smb_server_cap_nt_smbs = -1;
static int hf_smb_server_cap_rpc_remote_apis = -1;
static int hf_smb_server_cap_nt_status = -1;
static int hf_smb_server_cap_level_ii_oplocks = -1;
static int hf_smb_server_cap_lock_and_read = -1;
static int hf_smb_server_cap_nt_find = -1;
static int hf_smb_server_cap_dfs = -1;
static int hf_smb_server_cap_infolevel_passthru = -1;
static int hf_smb_server_cap_large_readx = -1;
static int hf_smb_server_cap_large_writex = -1;
static int hf_smb_server_cap_unix = -1;
static int hf_smb_server_cap_reserved = -1;
static int hf_smb_server_cap_bulk_transfer = -1;
static int hf_smb_server_cap_compressed_data = -1;
static int hf_smb_server_cap_extended_security = -1;
static int hf_smb_system_time = -1;
static int hf_smb_unknown = -1;
static int hf_smb_dir_name = -1;
static int hf_smb_echo_count = -1;
static int hf_smb_echo_data = -1;
static int hf_smb_echo_seq_num = -1;
static int hf_smb_max_buf_size = -1;
static int hf_smb_password = -1;
static int hf_smb_path = -1;
static int hf_smb_service = -1;
static int hf_smb_move_flags_file = -1;
static int hf_smb_move_flags_dir = -1;
static int hf_smb_move_flags_verify = -1;
static int hf_smb_count = -1;
static int hf_smb_file_name = -1;
static int hf_smb_open_function_open = -1;
static int hf_smb_open_function_create = -1;
static int hf_smb_fid = -1;
static int hf_smb_file_attr_read_only = -1;
static int hf_smb_file_attr_hidden = -1;
static int hf_smb_file_attr_system = -1;
static int hf_smb_file_attr_volume = -1;
static int hf_smb_file_attr_directory = -1;
static int hf_smb_file_attr_archive = -1;
static int hf_smb_file_attr_device = -1;
static int hf_smb_file_attr_normal = -1;
static int hf_smb_file_attr_temporary = -1;
static int hf_smb_file_attr_sparse = -1;
static int hf_smb_file_attr_reparse = -1;
static int hf_smb_file_attr_compressed = -1;
static int hf_smb_file_attr_offline = -1;
static int hf_smb_file_attr_not_content_indexed = -1;
static int hf_smb_file_attr_encrypted = -1;
static int hf_smb_file_size = -1;
static int hf_smb_last_write_time = -1;
static int hf_smb_search_attribute_read_only = -1;
static int hf_smb_search_attribute_hidden = -1;
static int hf_smb_search_attribute_system = -1;
static int hf_smb_search_attribute_volume = -1;
static int hf_smb_search_attribute_directory = -1;
static int hf_smb_search_attribute_archive = -1;
static int hf_smb_access_mode = -1;
static int hf_smb_access_sharing = -1;
static int hf_smb_access_locality = -1;
static int hf_smb_access_caching = -1;
static int hf_smb_access_writetru = -1;
static int hf_smb_create_time = -1;
static int hf_smb_create_dos_date = -1;
static int hf_smb_create_dos_time = -1;
static int hf_smb_last_write_date = -1;
static int hf_smb_last_write_dos_date = -1;
static int hf_smb_last_write_dos_time = -1;
static int hf_smb_access_time = -1;
static int hf_smb_access_dos_date = -1;
static int hf_smb_access_dos_time = -1;
static int hf_smb_old_file_name = -1;
static int hf_smb_offset = -1;
static int hf_smb_remaining = -1;
static int hf_smb_padding = -1;
static int hf_smb_file_data = -1;
static int hf_smb_data_len = -1;
static int hf_smb_seek_mode = -1;
static int hf_smb_data_size = -1;
static int hf_smb_alloc_size = -1;
static int hf_smb_max_count = -1;
static int hf_smb_min_count = -1;
static int hf_smb_timeout = -1;
static int hf_smb_high_offset = -1;
static int hf_smb_units = -1;
static int hf_smb_bpu = -1;
static int hf_smb_blocksize = -1;
static int hf_smb_freeunits = -1;


static gint ett_smb = -1;
static gint ett_smb_hdr = -1;
static gint ett_smb_command = -1;
static gint ett_smb_fileattributes = -1;
static gint ett_smb_capabilities = -1;
static gint ett_smb_aflags = -1;
static gint ett_smb_dialect = -1;
static gint ett_smb_dialects = -1;
static gint ett_smb_mode = -1;
static gint ett_smb_rawmode = -1;
static gint ett_smb_flags = -1;
static gint ett_smb_flags2 = -1;
static gint ett_smb_desiredaccess = -1;
static gint ett_smb_search = -1;
static gint ett_smb_file = -1;
static gint ett_smb_openfunction = -1;
static gint ett_smb_filetype = -1;
static gint ett_smb_openaction = -1;
static gint ett_smb_writemode = -1;
static gint ett_smb_lock_type = -1;
static gint ett_smb_ssetupandxaction = -1;
static gint ett_smb_optionsup = -1;
static gint ett_smb_time_date = -1;
static gint ett_smb_64bit_time = -1;
static gint ett_smb_move_flags = -1;
static gint ett_smb_file_attributes = -1;


static char *decode_smb_name(unsigned char);
static int dissect_smb_command(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree, guint8 cmd);
static const gchar *get_unicode_or_ascii_string_tvb(tvbuff_t *tvb, int *offsetp, packet_info *pinfo, int *len, gboolean nopad, gboolean exactlen);


#define WORD_COUNT	\
	/* Word Count */				\
	wc = tvb_get_guint8(tvb, offset);		\
	proto_tree_add_uint(tree, hf_smb_word_count,	\
		tvb, offset, 1, wc);			\
	offset += 1;					\
	if(wc==0) goto bytecount;

#define BYTE_COUNT	\
	bytecount:					\
	bc = tvb_get_letohs(tvb, offset);		\
	proto_tree_add_uint(tree, hf_smb_byte_count,	\
			tvb, offset, 2, bc);		\
	offset += 2;					\
	if(bc==0) goto endofcommand;

#define END_OF_SMB	\
	endofcommand:


/* XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
   These variables and functions are used to match
   responses with calls
   XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX */
static GMemChunk *smb_info_chunk = NULL;
static int smb_info_init_count = 200;
static GHashTable *smb_info_table = NULL;

static gint
smb_info_equal(gconstpointer k1, gconstpointer k2)
{
	smb_info_t *key1 = (smb_info_t *)k1;
	smb_info_t *key2 = (smb_info_t *)k2;
	gint res;

	/* make sure to always compare mid first since this is most
	   likely to differ ==> shortcircuiting the expression */
	res= (	(key1->mid==key2->mid)
		&&	(key1->pid==key2->pid)
		&&	(key1->uid==key2->uid)
		&&	(key1->cmd==key2->cmd)
		&&	(key1->tid==key2->tid)
		&&	(ADDRESSES_EQUAL(key1->src, key2->src))
		&&	(ADDRESSES_EQUAL(key1->dst, key2->dst)) );

	return res;
}

static guint
smb_info_hash(gconstpointer k)
{
	smb_info_t *key = (smb_info_t *)k;

	/* multiplex id is very likely to differ between calls
	   it should be sufficient for a good distribution of hash
	   values.
	*/
	return key->mid;
}
 
static gboolean
free_all_smb_info(gpointer key_arg, gpointer value, gpointer user_data)
{
	smb_info_t *key = (smb_info_t *)key_arg;

	if((key->src)&&(key->src->data)){
		g_free((gpointer)key->src->data);
		key->src->data = NULL;
		g_free((gpointer)key->src);
		key->src = NULL;
	}

	if((key->dst)&&(key->dst->data)){
		g_free((gpointer)key->dst->data);
		key->dst->data = NULL;
		g_free((gpointer)key->dst);
		key->dst = NULL;
	}
 
	return TRUE;
}

void
smb_info_init(void)
{
	if(smb_info_table){
		g_hash_table_foreach_remove(smb_info_table,
			free_all_smb_info, NULL);
	} else {
		smb_info_table = g_hash_table_new(smb_info_hash,
			smb_info_equal);
	}

	if(smb_info_chunk){
		g_mem_chunk_destroy(smb_info_chunk);
	}
	smb_info_chunk = g_mem_chunk_new("smb_info_chunk",
		sizeof(smb_info_t),
		smb_info_init_count*sizeof(smb_info_t),
		G_ALLOC_ONLY);
}
/* XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
   End of request/response matching functions
   XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX */

static const value_string buffer_format_vals[] = {
	{1,     "Data Block"},
	{2,     "Dialect"},
	{3,     "Pathname"},
	{4,     "ASCII"},
	{5,     "Variable Block"},
	{0,     NULL}
};

/*
 * UTIME - this is *almost* like a UNIX time stamp, except that it's
 * in seconds since January 1, 1970, 00:00:00 *local* time, not since
 * January 1, 1970, 00:00:00 GMT.
 *
 * This means we have to do some extra work to convert it.  This code is
 * based on the Samba code:
 *
 *	Unix SMB/Netbios implementation.
 *	Version 1.9.
 *	time handling functions
 *	Copyright (C) Andrew Tridgell 1992-1998
 */

/*
 * Yield the difference between *A and *B, in seconds, ignoring leap
 * seconds.
 */
#define TM_YEAR_BASE 1900

static int
tm_diff(struct tm *a, struct tm *b)
{
	int ay = a->tm_year + (TM_YEAR_BASE - 1);
	int by = b->tm_year + (TM_YEAR_BASE - 1);
	int intervening_leap_days =
	    (ay/4 - by/4) - (ay/100 - by/100) + (ay/400 - by/400);
	int years = ay - by;
	int days =
	    365*years + intervening_leap_days + (a->tm_yday - b->tm_yday);
	int hours = 24*days + (a->tm_hour - b->tm_hour);
	int minutes = 60*hours + (a->tm_min - b->tm_min);
	int seconds = 60*minutes + (a->tm_sec - b->tm_sec);

	return seconds;
}

/*
 * Return the UTC offset in seconds west of UTC, or 0 if it cannot be
 * determined.
 */
static int
TimeZone(time_t t)
{
	struct tm *tm = gmtime(&t);
	struct tm tm_utc;

	if (tm == NULL)
		return 0;
	tm_utc = *tm;
	tm = localtime(&t);
	if (tm == NULL)
		return 0;
	return tm_diff(&tm_utc,tm);
}

/*
 * Return the same value as TimeZone, but it should be more efficient.
 *
 * We keep a table of DST offsets to prevent calling localtime() on each 
 * call of this function. This saves a LOT of time on many unixes.
 *
 * Updated by Paul Eggert <eggert@twinsun.com>
 */
#ifndef CHAR_BIT
#define CHAR_BIT 8
#endif

#ifndef TIME_T_MIN
#define TIME_T_MIN ((time_t)0 < (time_t) -1 ? (time_t) 0 \
		    : ~ (time_t) 0 << (sizeof (time_t) * CHAR_BIT - 1))
#endif
#ifndef TIME_T_MAX
#define TIME_T_MAX (~ (time_t) 0 - TIME_T_MIN)
#endif

static int
TimeZoneFaster(time_t t)
{
	static struct dst_table {time_t start,end; int zone;} *tdt;
	static struct dst_table *dst_table = NULL;
	static int table_size = 0;
	int i;
	int zone = 0;

	if (t == 0)
		t = time(NULL);

	/* Tunis has a 8 day DST region, we need to be careful ... */
#define MAX_DST_WIDTH (365*24*60*60)
#define MAX_DST_SKIP (7*24*60*60)

	for (i = 0; i < table_size; i++) {
		if (t >= dst_table[i].start && t <= dst_table[i].end)
			break;
	}

	if (i < table_size) {
		zone = dst_table[i].zone;
	} else {
		time_t low,high;

		zone = TimeZone(t);
		if (dst_table == NULL)
			tdt = g_malloc(sizeof(dst_table[0])*(i+1));
		else
			tdt = g_realloc(dst_table, sizeof(dst_table[0])*(i+1));
		if (tdt == NULL) {
			if (dst_table)
				free(dst_table);
			table_size = 0;
		} else {
			dst_table = tdt;
			table_size++;
    
			dst_table[i].zone = zone; 
			dst_table[i].start = dst_table[i].end = t;
    
			/* no entry will cover more than 6 months */
			low = t - MAX_DST_WIDTH/2;
			if (t < low)
				low = TIME_T_MIN;
      
			high = t + MAX_DST_WIDTH/2;
			if (high < t)
				high = TIME_T_MAX;
      
			/*
			 * Widen the new entry using two bisection searches.
			 */
			while (low+60*60 < dst_table[i].start) {
				if (dst_table[i].start - low > MAX_DST_SKIP*2)
					t = dst_table[i].start - MAX_DST_SKIP;
				else
					t = low + (dst_table[i].start-low)/2;
				if (TimeZone(t) == zone)
					dst_table[i].start = t;
				else
					low = t;
			}

			while (high-60*60 > dst_table[i].end) {
				if (high - dst_table[i].end > MAX_DST_SKIP*2)
					t = dst_table[i].end + MAX_DST_SKIP;
				else
					t = high - (high-dst_table[i].end)/2;
				if (TimeZone(t) == zone)
					dst_table[i].end = t;
				else
					high = t;
			}
		}
	}
	return zone;
}

/*
 * Return the UTC offset in seconds west of UTC, adjusted for extra time
 * offset, for a local time value.  If ut = lt + LocTimeDiff(lt), then
 * lt = ut - TimeDiff(ut), but the converse does not necessarily hold near
 * daylight savings transitions because some local times are ambiguous.
 * LocTimeDiff(t) equals TimeDiff(t) except near daylight savings transitions.
 */
static int
LocTimeDiff(time_t lt)
{
	int d = TimeZoneFaster(lt);
	time_t t = lt + d;

	/* if overflow occurred, ignore all the adjustments so far */
	if (((t < lt) ^ (d < 0)))
		t = lt;

	/*
	 * Now t should be close enough to the true UTC to yield the
	 * right answer.
	 */
	return TimeZoneFaster(t);
}

static int
dissect_smb_UTIME(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int hf_date)
{
	guint32 timeval;
	nstime_t ts;
 
	timeval = tvb_get_letohl(tvb, offset);
	if (timeval == 0xffffffff) {
		proto_tree_add_text(tree, tvb, offset, 4,
		    "%s: No time specified (0xffffffff)",
		    proto_registrar_get_name(hf_date));
		offset += 4;
		return offset;
	}

	/*
	 * We add the local time offset.
	 */
	ts.secs = timeval + LocTimeDiff(timeval);
	ts.nsecs = 0;

	proto_tree_add_time(tree, hf_date, tvb, offset, 4, &ts);
	offset += 4;
 
	return offset;
}

static int
dissect_smb_64bit_time(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int offset, char *str, int hf_date)
{
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	nstime_t tv;

	/* XXXX we need some way to represent this as a time
	   properly. For now we display everything as 8 bytes*/

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 8,
			str);
		tree = proto_item_add_subtree(item, ett_smb_64bit_time);
	}

	proto_tree_add_bytes_format(tree, hf_smb_unknown, tvb, offset, 8, tvb_get_ptr(tvb, offset, 8), "%s: can't decode this yet", str);

	offset += 8;
	return offset;
}

static int
dissect_smb_datetime(tvbuff_t *tvb, packet_info *pinfo,
    proto_tree *parent_tree, int offset, int hf_date, int hf_dos_date,
    int hf_dos_time, gboolean time_first)
{
	guint16 dos_time, dos_date;
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	struct tm tm;
	time_t t;
	static const int mday_noleap[12] = {
		31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
	};
	static const int mday_leap[12] = {
		31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
	};
#define ISLEAP(y) (((y) % 4) == 0 && (((y) % 100) != 0 || ((y) % 400) == 0))
	nstime_t tv;

	if (time_first) {
		dos_time = tvb_get_letohs(tvb, offset);
		dos_date = tvb_get_letohs(tvb, offset+2);
	} else {
		dos_date = tvb_get_letohs(tvb, offset);
		dos_time = tvb_get_letohs(tvb, offset+2);
	}

	if ((dos_time == 0xffff && dos_time == 0xffff) ||
	    (dos_time == 0 && dos_time == 0)) {
		/*
		 * No date/time specified.
		 */
		if(parent_tree){
			proto_tree_add_text(parent_tree, tvb, offset, 4,
			    "%s: No time specified (0x%08x)",
			    proto_registrar_get_name(hf_date),
			    (dos_date << 16) | dos_time);
		}
		offset += 4;
		return offset;
	}

	tm.tm_sec = (dos_time&0x1f)*2;
	tm.tm_min = (dos_time>>5)&0x3f;
	tm.tm_hour = (dos_time>>11)&0x1f;
	tm.tm_mday = dos_date&0x1f;
	tm.tm_mon = ((dos_date>>5)&0x0f) - 1;
	tm.tm_year = ((dos_date>>9)&0x7f) + 1980 - 1900;
	tm.tm_isdst = -1;

	/*
	 * Do some sanity checks before calling "mktime()";
	 * "mktime()" doesn't do them, it "normalizes" out-of-range
	 * values.
	 */
	if (tm.tm_sec > 59 || tm.tm_min > 59 || tm.tm_hour > 23 ||
	   tm.tm_mon < 0 || tm.tm_mon > 11 ||
	   (ISLEAP(tm.tm_year + 1900) ?
	     tm.tm_mday > mday_leap[tm.tm_mon] :
	     tm.tm_mday > mday_noleap[tm.tm_mon]) ||
	     (t = mktime(&tm)) == -1) {
		/*
		 * Invalid date/time.
		 */
		if (parent_tree) {
			item = proto_tree_add_text(parent_tree, tvb, offset, 4,
			    "%s: Invalid time",
			    proto_registrar_get_name(hf_date));
			tree = proto_item_add_subtree(item, ett_smb_time_date);
			if (time_first) {
				proto_tree_add_uint_format(tree, hf_dos_time, tvb, offset, 2, dos_time, "DOS Time: %02d:%02d:%02d (0x%04x)", tm.tm_hour, tm.tm_min, tm.tm_sec, dos_time);
				proto_tree_add_uint_format(tree, hf_dos_date, tvb, offset+2, 2, dos_date, "DOS Date: %04d-%02d-%02d (0x%04x)", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, dos_date);
			} else {
				proto_tree_add_uint_format(tree, hf_dos_date, tvb, offset, 2, dos_date, "DOS Date: %04d-%02d-%02d (0x%04x)", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, dos_date);
				proto_tree_add_uint_format(tree, hf_dos_time, tvb, offset+2, 2, dos_time, "DOS Time: %02d:%02d:%02d (0x%04x)", tm.tm_hour, tm.tm_min, tm.tm_sec, dos_time);
			}
		}
		offset += 4;
		return offset;
	}

	tv.secs = t;
	tv.nsecs = 0;

	if(parent_tree){
		item = proto_tree_add_time(parent_tree, hf_date, tvb, offset, 4, &tv);
		tree = proto_item_add_subtree(item, ett_smb_time_date);
		if (time_first) {
			proto_tree_add_uint_format(tree, hf_dos_time, tvb, offset, 2, dos_time, "DOS Time: %02d:%02d:%02d (0x%04x)", tm.tm_hour, tm.tm_min, tm.tm_sec, dos_time);
			proto_tree_add_uint_format(tree, hf_dos_date, tvb, offset+2, 2, dos_date, "DOS Date: %04d-%02d-%02d (0x%04x)", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, dos_date);
		} else {
			proto_tree_add_uint_format(tree, hf_dos_date, tvb, offset, 2, dos_date, "DOS Date: %04d-%02d-%02d (0x%04x)", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, dos_date);
			proto_tree_add_uint_format(tree, hf_dos_time, tvb, offset+2, 2, dos_time, "DOS Time: %02d:%02d:%02d (0x%04x)", tm.tm_hour, tm.tm_min, tm.tm_sec, dos_time);
		}
	}

	offset += 4;

	return offset;
}


static const value_string da_access_vals[] = {
	{ 0x00,		"Open for reading"},
	{ 0x01,		"Open for writing"},
	{ 0x02,		"Open for reading and writing"},
	{ 0x03,		"Open for execute"},
	{0, NULL}
};
static const value_string da_sharing_vals[] = {
	{ 0x00,		"Compatibility mode"},
	{ 0x01,		"Deny read/write/execute (exclusive)"},
	{ 0x02,		"Deny write"},
	{ 0x03,		"Deny read/execute"},
	{ 0x04,		"Deny none"},
	{0, NULL}
};
static const value_string da_locality_vals[] = {
	{ 0x00,		"Locality of reference unknown"},
	{ 0x01,		"Mainly sequential access"},
	{ 0x02,		"Mainly random access"},
	{ 0x03,		"Random access with some locality"},
	{0, NULL}
};
static const true_false_string tfs_da_caching = {
	"Do NOT cache this file",
	"CACHING permitted on this file"
};
static const true_false_string tfs_da_writetru = {
	"Writethrough ENABLED",
	"Writethrough DISABLED"
};
static int
dissect_access(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int offset, char *type)
{
	guint16 mask;
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	mask = tvb_get_letohs(tvb, offset);

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 2,
			"%s Access: 0x%04x", type, mask);
		tree = proto_item_add_subtree(item, ett_smb_desiredaccess);
	}

	proto_tree_add_boolean(tree, hf_smb_access_writetru,
		tvb, offset, 2, mask);
	proto_tree_add_boolean(tree, hf_smb_access_caching,
		tvb, offset, 2, mask);
	proto_tree_add_uint(tree, hf_smb_access_locality,
		tvb, offset, 2, mask);
	proto_tree_add_uint(tree, hf_smb_access_sharing,
		tvb, offset, 2, mask);
	proto_tree_add_uint(tree, hf_smb_access_mode,
		tvb, offset, 2, mask);

	offset += 2;

	return offset;
}

#define FILE_ATTRIBUTE_READ_ONLY		0x00000001
#define FILE_ATTRIBUTE_HIDDEN			0x00000002
#define FILE_ATTRIBUTE_SYSTEM			0x00000004
#define FILE_ATTRIBUTE_VOLUME			0x00000008
#define FILE_ATTRIBUTE_DIRECTORY		0x00000010
#define FILE_ATTRIBUTE_ARCHIVE			0x00000020
#define FILE_ATTRIBUTE_DEVICE			0x00000040
#define FILE_ATTRIBUTE_NORMAL			0x00000080
#define FILE_ATTRIBUTE_TEMPORARY		0x00000100
#define FILE_ATTRIBUTE_SPARSE			0x00000200
#define FILE_ATTRIBUTE_REPARSE			0x00000400
#define FILE_ATTRIBUTE_COMPRESSED		0x00000800
#define FILE_ATTRIBUTE_OFFLINE			0x00001000
#define FILE_ATTRIBUTE_NOT_CONTENT_INDEXED	0x00002000
#define FILE_ATTRIBUTE_ENCRYPTED		0x00004000

/*
 * These are flags to be used in NT Create operations.
 */
#define FILE_ATTRIBUTE_WRITE_THROUGH		0x80000000
#define FILE_ATTRIBUTE_NO_BUFFERING		0x20000000
#define FILE_ATTRIBUTE_RANDOM_ACCESS		0x10000000
#define FILE_ATTRIBUTE_SEQUENTIAL_SCAN		0x08000000
#define FILE_ATTRIBUTE_DELETE_ON_CLOSE		0x04000000
#define FILE_ATTRIBUTE_BACKUP_SEMANTICS		0x02000000
#define FILE_ATTRIBUTE_POSIX_SEMANTICS		0x01000000

static const true_false_string tfs_file_attribute_write_through = {
	"This object requires WRITE THROUGH",
	"This object does NOT require write through",
};
static const true_false_string tfs_file_attribute_no_buffering = {
	"This object requires NO BUFFERING",
	"This object can be buffered",
};
static const true_false_string tfs_file_attribute_random_access = {
	"This object will be RANDOM ACCESSed",
	"Random access is NOT requested",
};
static const true_false_string tfs_file_attribute_sequential_scan = {
	"This object is optimized for SEQUENTIAL SCAN",
	"This object is NOT optimized for sequential scan",
};
static const true_false_string tfs_file_attribute_delete_on_close = {
	"This object will be DELETED ON CLOSE",
	"This object will not be deleted on close",
};
static const true_false_string tfs_file_attribute_backup_semantics = {
	"This object supports BACKUP SEMANTICS",
	"This object does NOT support backup semantics",
};
static const true_false_string tfs_file_attribute_posix_semantics = {
	"This object supports POSIX SEMANTICS",
	"This object does NOT support posix semantics",
};
static const true_false_string tfs_file_attribute_read_only = {
	"This file is READ ONLY",
	"This file is NOT read only",
};
static const true_false_string tfs_file_attribute_hidden = {
	"This is a HIDDEN file",
	"This is NOT a hidden file"
};
static const true_false_string tfs_file_attribute_system = {
	"This is a SYSTEM file",
	"This is NOT a system file"
};
static const true_false_string tfs_file_attribute_volume = {
	"This is a volume ID",
	"This is NOT a volume ID"
};
static const true_false_string tfs_file_attribute_directory = {
	"This is a DIRECTORY",
	"This is NOT a directory"
};
static const true_false_string tfs_file_attribute_archive = {
	"This is an ARCHIVE file",
	"This is NOT an archive file"
};
static const true_false_string tfs_file_attribute_device = {
	"This is a DEVICE",
	"This is NOT a device"
};
static const true_false_string tfs_file_attribute_normal = {
	"This file is an ordinary file",
	"This file has some attribute set"
};
static const true_false_string tfs_file_attribute_temporary = {
	"This is a TEMPORARY file",
	"This is NOT a temporary file"
};
static const true_false_string tfs_file_attribute_sparse = {
	"This is a SPARSE file",
	"This is NOT a sparse file"
};
static const true_false_string tfs_file_attribute_reparse = {
	"This file has an associated REPARSE POINT",
	"This file does NOT have an associated reparse point"
};
static const true_false_string tfs_file_attribute_compressed = {
	"This is a COMPRESSED file",
	"This is NOT a compressed file"
};
static const true_false_string tfs_file_attribute_offline = {
	"This file is OFFLINE",
	"This file is NOT offline"
};
static const true_false_string tfs_file_attribute_not_content_indexed = {
	"This file MAY NOT be indexed by the CONTENT INDEXING service",
	"This file MAY be indexed by the content indexing service"
};
static const true_false_string tfs_file_attribute_encrypted = {
	"This is an ENCRYPTED file",
	"This is NOT an encrypted file"
};

static int
dissect_file_attributes(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int offset)
{
	guint16 mask;
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	mask = tvb_get_letohs(tvb, offset);

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 2,
			"File Attributes: 0x%04x", mask);
		tree = proto_item_add_subtree(item, ett_smb_file_attributes);
	}
	proto_tree_add_boolean(tree, hf_smb_file_attr_read_only,
		tvb, offset, 2, mask);
	proto_tree_add_boolean(tree, hf_smb_file_attr_hidden,
		tvb, offset, 2, mask);
	proto_tree_add_boolean(tree, hf_smb_file_attr_system,
		tvb, offset, 2, mask);
	proto_tree_add_boolean(tree, hf_smb_file_attr_volume,
		tvb, offset, 2, mask);
	proto_tree_add_boolean(tree, hf_smb_file_attr_directory,
		tvb, offset, 2, mask);
	proto_tree_add_boolean(tree, hf_smb_file_attr_archive,
		tvb, offset, 2, mask);

	offset += 2;

	return offset;
}

static int
dissect_search_attributes(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int offset)
{
	guint16 mask;
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	mask = tvb_get_letohs(tvb, offset);

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 2,
			"Search Attributes: 0x%04x", mask);
		tree = proto_item_add_subtree(item, ett_smb_search);
	}

	proto_tree_add_boolean(tree, hf_smb_search_attribute_read_only,
		tvb, offset, 2, mask);
	proto_tree_add_boolean(tree, hf_smb_search_attribute_hidden,
		tvb, offset, 2, mask);
	proto_tree_add_boolean(tree, hf_smb_search_attribute_system,
		tvb, offset, 2, mask);	
	proto_tree_add_boolean(tree, hf_smb_search_attribute_volume,
		tvb, offset, 2, mask);
	proto_tree_add_boolean(tree, hf_smb_search_attribute_directory,
		tvb, offset, 2, mask);
	proto_tree_add_boolean(tree, hf_smb_search_attribute_archive,
		tvb, offset, 2, mask);

	offset += 2;
	return offset;
}

static int
dissect_extended_file_attributes(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int offset)
{
	guint32 mask;
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	mask = tvb_get_letohl(tvb, offset);

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 2,
			"File Attributes: 0x%08x", mask);
		tree = proto_item_add_subtree(item, ett_smb_file_attributes);
	}
	proto_tree_add_boolean(tree, hf_smb_file_attr_read_only,
		tvb, offset, 2, mask);
	proto_tree_add_boolean(tree, hf_smb_file_attr_hidden,
		tvb, offset, 2, mask);
	proto_tree_add_boolean(tree, hf_smb_file_attr_system,
		tvb, offset, 2, mask);
	proto_tree_add_boolean(tree, hf_smb_file_attr_volume,
		tvb, offset, 2, mask);
	proto_tree_add_boolean(tree, hf_smb_file_attr_directory,
		tvb, offset, 2, mask);
	proto_tree_add_boolean(tree, hf_smb_file_attr_archive,
		tvb, offset, 2, mask);
	proto_tree_add_boolean(tree, hf_smb_file_attr_device,
		tvb, offset, 2, mask);
	proto_tree_add_boolean(tree, hf_smb_file_attr_normal,
		tvb, offset, 2, mask);
	proto_tree_add_boolean(tree, hf_smb_file_attr_temporary,
		tvb, offset, 2, mask);
	proto_tree_add_boolean(tree, hf_smb_file_attr_sparse,
		tvb, offset, 2, mask);
	proto_tree_add_boolean(tree, hf_smb_file_attr_reparse,
		tvb, offset, 2, mask);
	proto_tree_add_boolean(tree, hf_smb_file_attr_compressed,
		tvb, offset, 2, mask);
	proto_tree_add_boolean(tree, hf_smb_file_attr_offline,
		tvb, offset, 2, mask);
	proto_tree_add_boolean(tree, hf_smb_file_attr_not_content_indexed,
		tvb, offset, 2, mask);
	proto_tree_add_boolean(tree, hf_smb_file_attr_encrypted,
		tvb, offset, 2, mask);

	offset += 2;

	return offset;
}


#define SERVER_CAP_RAW_MODE            0x00000001
#define SERVER_CAP_MPX_MODE            0x00000002
#define SERVER_CAP_UNICODE             0x00000004
#define SERVER_CAP_LARGE_FILES         0x00000008
#define SERVER_CAP_NT_SMBS             0x00000010
#define SERVER_CAP_RPC_REMOTE_APIS     0x00000020
#define SERVER_CAP_STATUS32            0x00000040
#define SERVER_CAP_LEVEL_II_OPLOCKS    0x00000080
#define SERVER_CAP_LOCK_AND_READ       0x00000100
#define SERVER_CAP_NT_FIND             0x00000200
#define SERVER_CAP_DFS                 0x00001000
#define SERVER_CAP_INFOLEVEL_PASSTHRU  0x00002000
#define SERVER_CAP_LARGE_READX         0x00004000
#define SERVER_CAP_LARGE_WRITEX        0x00008000
#define SERVER_CAP_UNIX                0x00800000
#define SERVER_CAP_RESERVED            0x02000000
#define SERVER_CAP_BULK_TRANSFER       0x20000000
#define SERVER_CAP_COMPRESSED_DATA     0x40000000
#define SERVER_CAP_EXTENDED_SECURITY   0x80000000
static const true_false_string tfs_server_cap_raw_mode = {
	"Read Raw and Write Raw are supported",
	"Read Raw and Write Raw are not supported"
};
static const true_false_string tfs_server_cap_mpx_mode = {
	"Read Mpx and Write Mpx are supported",
	"Read Mpx and Write Mpx are not supported"
};
static const true_false_string tfs_server_cap_unicode = {
	"Unicode strings are supported",
	"Unicode strings are not supported"
};
static const true_false_string tfs_server_cap_large_files = {
	"Large files are supported",
	"Large files are not supported",
};
static const true_false_string tfs_server_cap_nt_smbs = {
	"NT SMBs are supported",
	"NT SMBs are not supported"
};
static const true_false_string tfs_server_cap_rpc_remote_apis = {
	"RPC remote APIs are supported",
	"RPC remote APIs are not supported"
};
static const true_false_string tfs_server_cap_nt_status = {
	"NT status codes are supported",
	"NT status codes are not supported"
};
static const true_false_string tfs_server_cap_level_ii_oplocks = {
	"Level 2 oplocks are supported",
	"Level 2 oplocks are not supported"
};
static const true_false_string tfs_server_cap_lock_and_read = {
	"Lock and Read is supported",
	"Lock and Read is not supported"
};
static const true_false_string tfs_server_cap_nt_find = {
	"NT Find is supported",
	"NT Find is not supported"
};
static const true_false_string tfs_server_cap_dfs = {
	"Dfs is supported",
	"Dfs is not supported"
};
static const true_false_string tfs_server_cap_infolevel_passthru = {
	"NT information level request passthrough is supported",
	"NT information level request passthrough is not supported"
};
static const true_false_string tfs_server_cap_large_readx = {
	"Large Read andX is supported",
	"Large Read andX is not supported"
};
static const true_false_string tfs_server_cap_large_writex = {
	"Large Write andX is supported",
	"Large Write andX is not supported"
};
static const true_false_string tfs_server_cap_unix = {
	"UNIX extensions are supported",
	"UNIX extensions are not supported"
};
static const true_false_string tfs_server_cap_reserved = {
	"Reserved",
	"Reserved"
};
static const true_false_string tfs_server_cap_bulk_transfer = {
	"Bulk Read and Bulk Write are supported",
	"Bulk Read and Bulk Write are not supported"
};
static const true_false_string tfs_server_cap_compressed_data = {
	"Compressed data transfer is supported",
	"Compressed data transfer is not supported"
};
static const true_false_string tfs_server_cap_extended_security = {
	"Extended security exchanges are supported",
	"Extended security exchanges are not supported"
};
static int
dissect_negprot_capabilities(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int offset)
{
	guint32 mask;
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	mask = tvb_get_letohl(tvb, offset);

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 4, "Capabilities: 0x%08x", mask);
		tree = proto_item_add_subtree(item, ett_smb_capabilities);
	}

	proto_tree_add_boolean(tree, hf_smb_server_cap_raw_mode,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_server_cap_mpx_mode,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_server_cap_unicode,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_server_cap_large_files,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_server_cap_nt_smbs,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_server_cap_rpc_remote_apis,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_server_cap_nt_status,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_server_cap_level_ii_oplocks,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_server_cap_lock_and_read,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_server_cap_nt_find,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_server_cap_dfs,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_server_cap_infolevel_passthru,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_server_cap_large_readx,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_server_cap_large_writex,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_server_cap_unix,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_server_cap_reserved,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_server_cap_bulk_transfer,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_server_cap_compressed_data,
		tvb, offset, 4, mask);
	proto_tree_add_boolean(tree, hf_smb_server_cap_extended_security,
		tvb, offset, 4, mask);

	return mask;
}

#define RAWMODE_READ   0x01
#define RAWMODE_WRITE  0x02
static const true_false_string tfs_rm_read = {
	"Read Raw is supported",
	"Read Raw is not supported"
};
static const true_false_string tfs_rm_write = {
	"Write Raw is supported",
	"Write Raw is not supported"
};

static int
dissect_negprot_rawmode(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int offset)
{
	guint16 mask;
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	mask = tvb_get_letohs(tvb, offset);

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 2, "Raw Mode: 0x%04x", mask);
		tree = proto_item_add_subtree(item, ett_smb_rawmode);
	}

	proto_tree_add_boolean(tree, hf_smb_rm_read, tvb, offset, 2, mask);
	proto_tree_add_boolean(tree, hf_smb_rm_write, tvb, offset, 2, mask);

	offset += 2;

	return offset;
}

#define SECURITY_MODE_MODE             0x01
#define SECURITY_MODE_PASSWORD         0x02
#define SECURITY_MODE_SIGNATURES       0x04
#define SECURITY_MODE_SIG_REQUIRED     0x08
static const true_false_string tfs_sm_mode = {
	"USER security mode",
	"SHARE security mode"
};
static const true_false_string tfs_sm_password = {
	"ENCRYPTED password. Use challenge/response",
	"PLAINTEXT password"
};
static const true_false_string tfs_sm_signatures = {
	"Security signatures ENABLED",
	"Security signatures NOT enabled"
};
static const true_false_string tfs_sm_sig_required = {
	"Security signatures REQUIRED",
	"Security signatures NOT required"
};

static int
dissect_negprot_security_mode(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int offset, int wc)
{
	guint16 mask = 0;
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	switch(wc){
	case 13:
		mask = tvb_get_letohs(tvb, offset);
		item = proto_tree_add_text(parent_tree, tvb, offset, 2,
				"Security Mode: 0x%04x", mask);
		tree = proto_item_add_subtree(item, ett_smb_mode);
		proto_tree_add_boolean(tree, hf_smb_sm_mode16, tvb, offset, 2, mask);
		proto_tree_add_boolean(tree, hf_smb_sm_password16, tvb, offset, 2, mask);
		offset += 2;
		break;

	case 17:
		mask = tvb_get_guint8(tvb, offset);
		item = proto_tree_add_text(parent_tree, tvb, offset, 1,
				"Security Mode: 0x%02x", mask);
		tree = proto_item_add_subtree(item, ett_smb_mode);
		proto_tree_add_boolean(tree, hf_smb_sm_mode, tvb, offset, 1, mask);
		proto_tree_add_boolean(tree, hf_smb_sm_password, tvb, offset, 1, mask);
		proto_tree_add_boolean(tree, hf_smb_sm_signatures, tvb, offset, 1, mask);
		proto_tree_add_boolean(tree, hf_smb_sm_sig_required, tvb, offset, 1, mask);
		offset += 1;
		break;
	}

	return offset;
}

static int
dissect_negprot_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	proto_item *it = NULL;
	proto_tree *tr = NULL;
	guint16 bc;
	guint8 wc;

	WORD_COUNT;

	BYTE_COUNT;

	if(tree){
		it = proto_tree_add_text(tree, tvb, offset, bc,
				"Requested Dialects");
		tr = proto_item_add_subtree(it, ett_smb_dialects);
	}

	while(bc){
		int len;
		int old_offset = offset;
		const guint8 *str;
		proto_item *dit = NULL;
		proto_tree *dtr = NULL;

		len = tvb_strsize(tvb, offset+1);
		str = tvb_get_ptr(tvb, offset+1, len);

		if(tr){
			dit = proto_tree_add_text(tr, tvb, offset, len+1,
					"Dialect: %s", str);
			dtr = proto_item_add_subtree(dit, ett_smb_dialect);
		}

		/* Buffer Format */
		proto_tree_add_uint(dtr, hf_smb_buffer_format, tvb, offset, 1,
			tvb_get_guint8(tvb, offset));
		offset += 1;
		bc -= 1;

		/*Dialect Name */
		proto_tree_add_string(dtr, hf_smb_dialect_name, tvb, offset,
			len, str);
		offset += len;
		bc -= len;
	}

	END_OF_SMB

	return offset;
}

static int
dissect_negprot_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	guint8 wc;
	guint16 dialect;
	const char *dn;
	int dn_len;
	guint16 bc;
	guint16 ekl=0;
	guint32 caps=0;
	gint16 tz;


	WORD_COUNT;

	/* Dialect Index */
	dialect = tvb_get_letohs(tvb, offset);
	switch(wc){
	case 1:
		if(dialect==0xffff){
			proto_tree_add_uint_format(tree, hf_smb_dialect_index,
				tvb, offset, 2, dialect,
				"Selected Index: -1, PC NETWORK PROGRAM 1.0 choosen");
		} else {
			proto_tree_add_uint(tree, hf_smb_dialect_index,
				tvb, offset, 2, dialect);
		}
		break;
	case 13:
		proto_tree_add_uint_format(tree, hf_smb_dialect_index,
			tvb, offset, 2, dialect,
			"Dialect Index: %u, Greater than CORE PROTOCOL and up to LANMAN2.1", dialect);
		break;
	case 17:
		proto_tree_add_uint_format(tree, hf_smb_dialect_index,
			tvb, offset, 2, dialect,
			"Dialect Index: %u, greater than LANMAN2.1", dialect);
		break;
	default:
		proto_tree_add_text(tree, tvb, offset, wc*2,
			"Words for unknown response format");
		offset += wc*2;
		goto bytecount;
	}
	offset += 2;

	switch(wc){
	case 13:
		/* Security Mode */
		offset = dissect_negprot_security_mode(tvb, pinfo, tree, offset,
				wc);

		/* Maximum Transmit Buffer Size */
		proto_tree_add_uint(tree, hf_smb_max_trans_buf_size,
			tvb, offset, 2, tvb_get_letohs(tvb, offset));
		offset += 2;

		/* Maximum Multiplex Count */
		proto_tree_add_uint(tree, hf_smb_max_mpx_count,
			tvb, offset, 2, tvb_get_letohs(tvb, offset));
		offset += 2;

		/* Maximum Vcs Number */
		proto_tree_add_uint(tree, hf_smb_max_vcs_num,
			tvb, offset, 2, tvb_get_letohs(tvb, offset));
		offset += 2;

		/* raw mode */
		offset = dissect_negprot_rawmode(tvb, pinfo, tree, offset);

		/* session key */
		proto_tree_add_uint(tree, hf_smb_session_key,
			tvb, offset, 4, tvb_get_letohl(tvb, offset));
		offset += 4;

		/* current time and date at server */
		offset = dissect_smb_datetime(tvb, pinfo, tree, offset, hf_smb_server_date_time, hf_smb_server_smb_date, hf_smb_server_smb_time,
		    TRUE);

		/* time zone */
		tz = tvb_get_letohs(tvb, offset);
		proto_tree_add_int_format(tree, hf_smb_server_timezone, tvb, offset, 2, tz, "Server Time Zone: %d min from UTC", tz);
		offset += 2;

		/* encryption key length */
		ekl = tvb_get_letohs(tvb, offset);
		proto_tree_add_uint(tree, hf_smb_encryption_key_length, tvb, offset, 2, ekl);
		offset += 2;

		/* 2 reserved bytes */
		proto_tree_add_item(tree, hf_smb_reserved, tvb, offset, 2, TRUE);
		offset += 2;

		break;

	case 17:
		/* Security Mode */
		offset = dissect_negprot_security_mode(tvb, pinfo, tree, offset, wc);

		/* Maximum Multiplex Count */
		proto_tree_add_uint(tree, hf_smb_max_mpx_count,
			tvb, offset, 2, tvb_get_letohs(tvb, offset));
		offset += 2;

		/* Maximum Vcs Number */
		proto_tree_add_uint(tree, hf_smb_max_vcs_num,
			tvb, offset, 2, tvb_get_letohs(tvb, offset));
		offset += 2;

		/* Maximum Transmit Buffer Size */
		proto_tree_add_uint(tree, hf_smb_max_trans_buf_size,
			tvb, offset, 4, tvb_get_letohl(tvb, offset));
		offset += 4;

		/* maximum raw buffer size */
		proto_tree_add_uint(tree, hf_smb_max_raw_buf_size,
			tvb, offset, 4, tvb_get_letohl(tvb, offset));
		offset += 4;

		/* session key */
		proto_tree_add_uint(tree, hf_smb_session_key,
			tvb, offset, 4, tvb_get_letohl(tvb, offset));
		offset += 4;

		/* server capabilities */
		caps = dissect_negprot_capabilities(tvb, pinfo, tree, offset);
		offset += 4;

		/* system time */
		offset = dissect_smb_64bit_time(tvb, pinfo, tree, offset,
			       	"System Time", hf_smb_system_time);

		/* time zone */
		tz = tvb_get_letohs(tvb, offset);
		proto_tree_add_int_format(tree, hf_smb_server_timezone,
			tvb, offset, 2, tz,
			"Server Time Zone: %d min from UTC", tz);
		offset += 2;

		/* encryption key length */
		ekl = tvb_get_guint8(tvb, offset);
		proto_tree_add_uint(tree, hf_smb_encryption_key_length,
			tvb, offset, 1, ekl);
		offset += 1;

		break;
	}

	BYTE_COUNT;

	switch(wc){
	case 13:
		/* challange/ encryption key */
		if(ekl){
			proto_tree_add_item(tree, hf_smb_encryption_key, tvb, offset, ekl, TRUE);
			offset += ekl;
		}

		/* is this string optional ? */
		if(tvb_reported_length_remaining(tvb, offset)>0){
			/* domain */
			dn = get_unicode_or_ascii_string_tvb(tvb, &offset,
				pinfo, &dn_len, FALSE, FALSE);
			proto_tree_add_string(tree, hf_smb_primary_domain, tvb,
				offset, dn_len,dn);
			offset += dn_len;
		}
		break;

	case 17:
		if(!(caps&SERVER_CAP_EXTENDED_SECURITY)){
			smb_info_t *si;

			/* challange/ encryption key */
			if(ekl){
				proto_tree_add_bytes(tree, hf_smb_encryption_key,
					tvb, offset, ekl,
					tvb_get_ptr(tvb, offset, ekl));
				offset += ekl;
			}

			if(tvb_reported_length_remaining(tvb, offset)){
				/* domain */
				/* this string is special, unicode is flagged in caps */
				/* This string is NOT padded to be 16bit aligned. (seen in actual capture) */
				si = pinfo->private_data;
				si->unicode = (caps&SERVER_CAP_UNICODE);
				dn = get_unicode_or_ascii_string_tvb(tvb,
					&offset, pinfo, &dn_len, TRUE, FALSE);
				proto_tree_add_string(tree, hf_smb_primary_domain,
					tvb, offset, dn_len,dn);
				offset += dn_len;
			}
		} else {
			int len;

			/* guid */
			/* XXX - show it in the standard Microsoft format
			   for GUIDs? */
			proto_tree_add_bytes(tree, hf_smb_server_guid,
				tvb, offset, 16, tvb_get_ptr(tvb, offset, 16));
			offset += 16;

			/* security blob */
			/* XXX - is this ASN.1-encoded?  Is it a Kerberos
			   data structure, at least in NT 5.0-and-later
			   server replies? */
			len = tvb_reported_length_remaining(tvb, offset);
			if(len){
				proto_tree_add_bytes(tree, hf_smb_security_blob,
					tvb, offset, len,
					tvb_get_ptr(tvb, offset, len));
				offset += len;
			}
		}
		break;

	default:
		proto_tree_add_text(tree, tvb, offset, bc,
			"Bytes for unknown response format");
		offset += bc;
		goto endofcommand;
	}

	END_OF_SMB

	return offset;
}


static int
dissect_old_dir_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	int dn_len;
	const char *dn;
	guint8 wc;
	guint16 bc;

	WORD_COUNT;
 
	BYTE_COUNT;

	/* buffer format */
	proto_tree_add_uint(tree, hf_smb_buffer_format, tvb, offset, 1,
		tvb_get_guint8(tvb, offset));
	offset += 1;

	/* dir name */
	dn = get_unicode_or_ascii_string_tvb(tvb, &offset, pinfo, &dn_len,
		FALSE, FALSE);
	proto_tree_add_string(tree, hf_smb_dir_name, tvb, offset, dn_len,
		dn);
	offset += dn_len;

	if (check_col(pinfo->fd, COL_INFO)) {
		col_append_fstr(pinfo->fd, COL_INFO, ", Directory: %s", dn);
	}

	END_OF_SMB

	return offset;
}

static int
dissect_empty(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	guint8 wc;
	guint16 bc;
 
	WORD_COUNT;
 
	BYTE_COUNT;

	END_OF_SMB

	return offset;
}

static int
dissect_echo_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	guint16 ec, bc;
	guint8 wc;

	WORD_COUNT;

	/* echo count */
	ec = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint(tree, hf_smb_echo_count, tvb, offset, 2, ec);
	offset += 2;

	BYTE_COUNT;

	/* echo data */
	proto_tree_add_item(tree, hf_smb_echo_data, tvb, offset, bc, TRUE);
	offset += bc;

	END_OF_SMB

	return offset;
}

static int
dissect_echo_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	guint16 bc;
	guint8 wc;

	WORD_COUNT;

	/* echo sequence number */
	proto_tree_add_item(tree, hf_smb_echo_seq_num, tvb, offset, 2, TRUE);
	offset += 2;

	BYTE_COUNT;

	/* echo data */
	proto_tree_add_item(tree, hf_smb_echo_data, tvb, offset, bc, TRUE);
	offset += bc;

	END_OF_SMB

	return offset;
}

static int
dissect_tree_connect_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	guint8 wc;
	guint16 bc;

	WORD_COUNT;
 
	/* Maximum Buffer Size */
	proto_tree_add_item(tree, hf_smb_max_buf_size, tvb, offset, 2, TRUE);
	offset += 2;

	/* tid */
	proto_tree_add_item(tree, hf_smb_tid, tvb, offset, 2, TRUE);
	offset += 2;

	BYTE_COUNT;

	END_OF_SMB

	return offset;
}
 
static int
dissect_tree_connect_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	int an_len, pwlen;
	const char *an;
	guint8 wc;
	guint16 bc;

	WORD_COUNT;
 
	BYTE_COUNT;

	/* buffer format */
	proto_tree_add_uint(tree, hf_smb_buffer_format, tvb, offset, 1,
		tvb_get_guint8(tvb, offset));
	offset += 1;

	/* Path */
	an = get_unicode_or_ascii_string_tvb(tvb, &offset,
		pinfo, &an_len, FALSE, FALSE);
	proto_tree_add_string(tree, hf_smb_path, tvb,
		offset, an_len, an);
	offset += an_len;


	if (check_col(pinfo->fd, COL_INFO)) {
		col_append_fstr(pinfo->fd, COL_INFO, ", Path: %s", an);
	}

	/* buffer format */
	proto_tree_add_uint(tree, hf_smb_buffer_format, tvb, offset, 1,
		tvb_get_guint8(tvb, offset));
	offset += 1;

	/* password, ANSI */
	pwlen = tvb_strsize(tvb, offset);
	proto_tree_add_bytes(tree, hf_smb_password,
		tvb, offset, pwlen, tvb_get_ptr(tvb, offset, pwlen));
	offset += pwlen;

	/* buffer format */
	proto_tree_add_uint(tree, hf_smb_buffer_format, tvb, offset, 1,
		tvb_get_guint8(tvb, offset));
	offset += 1;

	/* Service */
	an = get_unicode_or_ascii_string_tvb(tvb, &offset,
		pinfo, &an_len, FALSE, FALSE);
	proto_tree_add_string(tree, hf_smb_service, tvb,
		offset, an_len, an);
	offset += an_len;

	END_OF_SMB

	return offset;
}


static const true_false_string tfs_of_create = {
	"CREATE file if it does not exist",
	"FAIL if file does not exist"
};
static const value_string of_open[] = {
	{ 0x00,		"Fail if file exists"},
	{ 0x01,		"Open file if it exists"},
	{ 0x02,		"Truncate file if it exists"},
	{0, NULL}
};
static int
dissect_open_function(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int offset)
{
	guint16 mask;
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	mask = tvb_get_letohs(tvb, offset);

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 2,
			"Open Function: 0x%04x", mask);
		tree = proto_item_add_subtree(item, ett_smb_openfunction);
	}

	proto_tree_add_boolean(tree, hf_smb_open_function_create,
		tvb, offset, 2, mask);
	proto_tree_add_uint(tree, hf_smb_open_function_open,
		tvb, offset, 2, mask);

	offset += 2;

	return offset;
}


static const true_false_string tfs_mf_file = {
	"Target must be a file",
	"Target needn't be a file"
 };
static const true_false_string tfs_mf_dir = {
	"Target must be a directory",
	"Target needn't be a directory"
};
static const true_false_string tfs_mf_verify = {
	"MUST verify all writes",
	"Don't have to verify writes"
};
static int
dissect_move_flags(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int offset)
{
	guint16 mask;
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	mask = tvb_get_letohs(tvb, offset);

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 2,
			"Flags: 0x%04x", mask);
		tree = proto_item_add_subtree(item, ett_smb_move_flags);
	}
 
	proto_tree_add_boolean(tree, hf_smb_move_flags_verify,
		tvb, offset, 2, mask);
	proto_tree_add_boolean(tree, hf_smb_move_flags_dir,
		tvb, offset, 2, mask);
	proto_tree_add_boolean(tree, hf_smb_move_flags_file,
		tvb, offset, 2, mask);

	offset += 2;

	return offset;
}

static int
dissect_move_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	int fn_len;
	guint16 tid;
	guint16 bc;
	guint8 wc;
	const char *fn;

	WORD_COUNT;

	/* tid */
	tid = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint_format(tree, hf_smb_tid, tvb, offset, 2, tid,
		"TID (target): 0x%04x", tid);
	offset += 2;

	/* open function */
	offset = dissect_open_function(tvb, pinfo, tree, offset);

	/* move flags */
	offset = dissect_move_flags(tvb, pinfo, tree, offset);

	BYTE_COUNT;

	/* buffer format */
	proto_tree_add_item(tree, hf_smb_buffer_format, tvb, offset, 1, TRUE);
	offset += 1;

	/* file name */
	fn = get_unicode_or_ascii_string_tvb(tvb, &offset, pinfo, &fn_len, FALSE, FALSE);
	proto_tree_add_string_format(tree, hf_smb_file_name, tvb, offset,
		fn_len,	fn, "Old File Name: %s", fn);
	offset += fn_len;

	if (check_col(pinfo->fd, COL_INFO)) {
		col_append_fstr(pinfo->fd, COL_INFO, ", Old Name: %s", fn);
	}

	/* buffer format */
	proto_tree_add_item(tree, hf_smb_buffer_format, tvb, offset, 1, TRUE);
	offset += 1;

	/* file name */
	fn = get_unicode_or_ascii_string_tvb(tvb, &offset, pinfo, &fn_len, FALSE, FALSE);
	proto_tree_add_string_format(tree, hf_smb_file_name, tvb, offset,
		fn_len,	fn, "New File Name: %s", fn);
	offset += fn_len;

	if (check_col(pinfo->fd, COL_INFO)) {
		col_append_fstr(pinfo->fd, COL_INFO, ", New Name: %s", fn);
	}

	END_OF_SMB

	return offset;
}

static int
dissect_move_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	int fn_len;
	const char *fn;
	guint8 wc;
	guint16 bc;

	WORD_COUNT;

	/* read count */
	proto_tree_add_item(tree, hf_smb_count, tvb, offset, 2, TRUE);
	offset += 2;

	BYTE_COUNT;

	/* buffer format */
	proto_tree_add_item(tree, hf_smb_buffer_format, tvb, offset, 1, TRUE);
	offset += 1;

	/* file name */
	fn = get_unicode_or_ascii_string_tvb(tvb, &offset, pinfo, &fn_len, FALSE, FALSE);
	proto_tree_add_string(tree, hf_smb_file_name, tvb, offset, fn_len,
		fn);
	offset += fn_len;

	END_OF_SMB

	return offset;
}

static int
dissect_open_file_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	int fn_len;
	const char *fn;
	guint8 wc;
	guint16 bc;

	WORD_COUNT;

	/* desired access */
	offset = dissect_access(tvb, pinfo, tree, offset, "Desired");

	/* Search Attributes */
	offset = dissect_search_attributes(tvb, pinfo, tree, offset);

	BYTE_COUNT;

	/* buffer format */
	proto_tree_add_item(tree, hf_smb_buffer_format, tvb, offset, 1, TRUE);
	offset += 1;

	/* file name */
	fn = get_unicode_or_ascii_string_tvb(tvb, &offset, pinfo, &fn_len, FALSE, FALSE);
	proto_tree_add_string(tree, hf_smb_file_name, tvb, offset, fn_len,
		fn);
	offset += fn_len;

	if (check_col(pinfo->fd, COL_INFO)) {
		col_append_fstr(pinfo->fd, COL_INFO, ", Path: %s", fn);
	}

	END_OF_SMB

	return offset;
}
 
static int
dissect_open_file_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	guint8 wc;
	guint16 bc;

	WORD_COUNT;

	/* fid */
	proto_tree_add_item(tree, hf_smb_fid, tvb, offset, 2, TRUE);
	offset += 2;

	/* File Attributes */
	offset = dissect_file_attributes(tvb, pinfo, tree, offset);

	/* last write time */
	offset = dissect_smb_UTIME(tvb, pinfo, tree, offset, hf_smb_last_write_time);
	
	/* File Size */
	proto_tree_add_item(tree, hf_smb_file_size, tvb, offset, 4, TRUE);
	offset += 4;

	/* granted access */
	offset = dissect_access(tvb, pinfo, tree, offset, "Granted");

	BYTE_COUNT;

	END_OF_SMB

	return offset;
}

static int
dissect_fid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	guint8 wc;
	guint16 bc;

	WORD_COUNT;

	/* fid */
	proto_tree_add_item(tree, hf_smb_fid, tvb, offset, 2, TRUE);
	offset += 2;

	BYTE_COUNT;

	END_OF_SMB

	return offset;
}

static int
dissect_create_file_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	int fn_len;
	const char *fn;
	guint8 wc;
	guint16 bc;

	WORD_COUNT;

	/* file attributes */
	offset = dissect_file_attributes(tvb, pinfo, tree, offset);

	/* creation time */
	offset = dissect_smb_UTIME(tvb, pinfo, tree, offset, hf_smb_create_time);

	BYTE_COUNT;

	/* buffer format */
	proto_tree_add_item(tree, hf_smb_buffer_format, tvb, offset, 1, TRUE);
	offset += 1;

	/* File Name */
	fn = get_unicode_or_ascii_string_tvb(tvb, &offset, pinfo, &fn_len, FALSE, FALSE);
	proto_tree_add_string(tree, hf_smb_file_name, tvb, offset, fn_len,
		fn);
	offset += fn_len;

	if (check_col(pinfo->fd, COL_INFO)) {
		col_append_fstr(pinfo->fd, COL_INFO, ", Path: %s", fn);
	}

	END_OF_SMB

	return offset;
}

static int
dissect_close_file_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	guint8 wc;
	guint16 bc;

	WORD_COUNT;

	/* fid */
	proto_tree_add_item(tree, hf_smb_fid, tvb, offset, 2, TRUE);
	offset += 2;

	/* last write time */
	offset = dissect_smb_UTIME(tvb, pinfo, tree, offset, hf_smb_last_write_time);

	BYTE_COUNT;

	END_OF_SMB

	return offset;
}

static int
dissect_delete_file_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	int fn_len;
	const char *fn;
	guint8 wc;
	guint16 bc;

	WORD_COUNT;

	/* search attributes */
	offset = dissect_search_attributes(tvb, pinfo, tree, offset);

	BYTE_COUNT;

	/* buffer format */
	proto_tree_add_item(tree, hf_smb_buffer_format, tvb, offset, 1, TRUE);
	offset += 1;

	/* file name */
	fn = get_unicode_or_ascii_string_tvb(tvb, &offset, pinfo, &fn_len, FALSE, FALSE);
	proto_tree_add_string(tree, hf_smb_file_name, tvb, offset, fn_len,
		fn);
	offset += fn_len;

	if (check_col(pinfo->fd, COL_INFO)) {
		col_append_fstr(pinfo->fd, COL_INFO, ", Path: %s", fn);
	}

	END_OF_SMB

	return offset;
}

static int
dissect_rename_file_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	int fn_len;
	const char *fn;
	guint8 wc;
	guint16 bc;

	WORD_COUNT;

	/* file attributes */
	offset = dissect_search_attributes(tvb, pinfo, tree, offset);

	BYTE_COUNT;

	/* buffer format */
	proto_tree_add_item(tree, hf_smb_buffer_format, tvb, offset, 1, TRUE);
	offset += 1;

	/* old file name */
	fn = get_unicode_or_ascii_string_tvb(tvb, &offset, pinfo, &fn_len, FALSE, FALSE);
	proto_tree_add_string(tree, hf_smb_old_file_name, tvb, offset, fn_len,
		fn);
	offset += fn_len;

	if (check_col(pinfo->fd, COL_INFO)) {
		col_append_fstr(pinfo->fd, COL_INFO, ", Old Name: %s", fn);
	}

	/* buffer format */
	proto_tree_add_item(tree, hf_smb_buffer_format, tvb, offset, 1, TRUE);
	offset += 1;

	/* file name */
	fn = get_unicode_or_ascii_string_tvb(tvb, &offset, pinfo, &fn_len, FALSE, FALSE);
	proto_tree_add_string(tree, hf_smb_file_name, tvb, offset, fn_len,
		fn);
	offset += fn_len;

	if (check_col(pinfo->fd, COL_INFO)) {
		col_append_fstr(pinfo->fd, COL_INFO, ", New Name: %s", fn);
	}

	END_OF_SMB

	return offset;
}

static int
dissect_query_information_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	guint16 bc;
	guint8 wc;
	const char *fn;
	int fn_len;

	WORD_COUNT;

	BYTE_COUNT;

	/* Buffer Format */
	proto_tree_add_uint(tree, hf_smb_buffer_format, tvb, offset, 1,
		tvb_get_guint8(tvb, offset));
	offset += 1;

	/* File Name */
	fn = get_unicode_or_ascii_string_tvb(tvb, &offset, pinfo, &fn_len, FALSE, FALSE);
	proto_tree_add_string(tree, hf_smb_file_name, tvb, offset, fn_len,
		fn);
	offset += fn_len;

	if (check_col(pinfo->fd, COL_INFO)) {
		col_append_fstr(pinfo->fd, COL_INFO, ", Path: %s", fn);
	}

	END_OF_SMB

	return offset;
}
 
static int
dissect_query_information_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	guint16 bc;
	guint8 wc;
	nstime_t ts;

	WORD_COUNT;

	/* File Attributes */
	offset = dissect_file_attributes(tvb, pinfo, tree, offset);

	/* Last Write Time */
	offset = dissect_smb_UTIME(tvb, pinfo, tree, offset, hf_smb_last_write_time);

	/* File Size */
	proto_tree_add_item(tree, hf_smb_file_size, tvb, offset, 4, TRUE);
	offset += 4;

	/* 10 reserved bytes */
	proto_tree_add_item(tree, hf_smb_reserved, tvb, offset, 10, TRUE);
	offset += 10;

	BYTE_COUNT;

	END_OF_SMB

	return offset;
}

static int
dissect_set_information_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	int fn_len;
	const char *fn;
	guint8 wc;
	guint16 bc;

	WORD_COUNT;

	/* file attributes */
	offset = dissect_file_attributes(tvb, pinfo, tree, offset);

	/* last write time */
	offset = dissect_smb_UTIME(tvb, pinfo, tree, offset, hf_smb_last_write_time);

	/* 10 reserved bytes */
	proto_tree_add_item(tree, hf_smb_reserved, tvb, offset, 10, TRUE);
	offset += 10;

	BYTE_COUNT;

	/* buffer format */
	proto_tree_add_item(tree, hf_smb_buffer_format, tvb, offset, 1, TRUE);
	offset += 1;

	/* file name */
	fn = get_unicode_or_ascii_string_tvb(tvb, &offset, pinfo, &fn_len, FALSE, FALSE);
	proto_tree_add_string(tree, hf_smb_file_name, tvb, offset, fn_len,
		fn);
	offset += fn_len;

	if (check_col(pinfo->fd, COL_INFO)) {
		col_append_fstr(pinfo->fd, COL_INFO, ", Path: %s", fn);
	}

	END_OF_SMB

	return offset;
}

static int
dissect_read_file_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	guint8 wc;
	guint16 bc;

	WORD_COUNT;

	/* fid */
	proto_tree_add_item(tree, hf_smb_fid, tvb, offset, 2, TRUE);
	offset += 2;

	/* read count */
	proto_tree_add_item(tree, hf_smb_count, tvb, offset, 2, TRUE);
	offset += 2;

	/* offset */
	proto_tree_add_item(tree, hf_smb_offset, tvb, offset, 4, TRUE);
	offset += 4;

	/* remaining */
	proto_tree_add_item(tree, hf_smb_remaining, tvb, offset, 2, TRUE);
	offset += 2;

	BYTE_COUNT;

	END_OF_SMB

	return offset;
}

static int
dissect_read_file_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	guint16 cnt=0, bc;
	guint8 wc;

	WORD_COUNT;

	/* read count */
	cnt = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint(tree, hf_smb_count, tvb, offset, 2, cnt);
	offset += 2;

	/* 8 reserved bytes */
	proto_tree_add_item(tree, hf_smb_reserved, tvb, offset, 8, TRUE);
	offset += 8;

	BYTE_COUNT;

	/* buffer format */
	proto_tree_add_item(tree, hf_smb_buffer_format, tvb, offset, 1, TRUE);
	offset += 1;
	bc -= 1;

	/* data len */
	if (bc < 2)
		return offset;
	proto_tree_add_item(tree, hf_smb_data_len, tvb, offset, 2, TRUE);
	offset += 2;
	bc -= 2;

	if (bc != 0) {
		/* file data */
		if(bc>tvb_length_remaining(tvb, offset)){
			int len;
			len = tvb_length_remaining(tvb, offset);
			proto_tree_add_bytes_format(tree, hf_smb_file_data, tvb, offset, len, tvb_get_ptr(tvb, offset, len),"File Data: Incomplete. Only %u of %u bytes", len, bc);
			offset += len;
		} else {
			proto_tree_add_item(tree, hf_smb_file_data, tvb, offset, bc, TRUE);
			offset += bc;
		}
	}

	END_OF_SMB

	return offset;
}

static int
dissect_lock_and_read_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	guint16 cnt, bc;
	guint8 wc;

	WORD_COUNT;

	/* read count */
	cnt = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint(tree, hf_smb_count, tvb, offset, 2, cnt);
	offset += 2;

	/* 8 reserved bytes */
	proto_tree_add_item(tree, hf_smb_reserved, tvb, offset, 8, TRUE);
	offset += 8;

	BYTE_COUNT;

	/* buffer format */
	proto_tree_add_item(tree, hf_smb_buffer_format, tvb, offset, 1, TRUE);
	offset += 1;
	bc -= 1;

	/* data len */
	proto_tree_add_item(tree, hf_smb_data_len, tvb, offset, 2, TRUE);
	offset += 2;

	END_OF_SMB

	return offset;
}


static int
dissect_write_file_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	guint16 cnt=0, bc;
	guint8 wc;

	WORD_COUNT;

	/* fid */
	proto_tree_add_item(tree, hf_smb_fid, tvb, offset, 2, TRUE);
	offset += 2;

	/* write count */
	cnt = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint(tree, hf_smb_count, tvb, offset, 2, cnt);
	offset += 2;

	/* offset */
	proto_tree_add_item(tree, hf_smb_offset, tvb, offset, 4, TRUE);
	offset += 4;

	/* remaining */
	proto_tree_add_item(tree, hf_smb_remaining, tvb, offset, 2, TRUE);
	offset += 2;

	BYTE_COUNT;

	/* buffer format */
	proto_tree_add_item(tree, hf_smb_buffer_format, tvb, offset, 1, TRUE);
	offset += 1;
	bc -= 1;

	/* data len */
	if (bc < 2)
		return offset;
	proto_tree_add_item(tree, hf_smb_data_len, tvb, offset, 2, TRUE);
	offset += 2;
	bc -= 2;

	if (bc != 0) {
		/* file data */
		if(bc>tvb_length_remaining(tvb, offset)){
			int len;
			len = tvb_length_remaining(tvb, offset);
			proto_tree_add_bytes_format(tree, hf_smb_file_data, tvb, offset, len, tvb_get_ptr(tvb, offset, len),"File Data: Incomplete. Only %d of %d bytes", len, bc);
			offset += len;
		} else {
			proto_tree_add_item(tree, hf_smb_file_data, tvb, offset, bc, TRUE);
			offset += bc;
		}
	}

	END_OF_SMB

	return offset;
}
 
static int
dissect_write_file_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	guint8 wc;
	guint16 bc;

	WORD_COUNT;

	/* write count */
	proto_tree_add_item(tree, hf_smb_count, tvb, offset, 2, TRUE);
	offset += 2;

	BYTE_COUNT;

	END_OF_SMB

	return offset;
}

static int
dissect_lock_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	guint8 wc;
	guint16 bc;

	WORD_COUNT;

	/* fid */
	proto_tree_add_item(tree, hf_smb_fid, tvb, offset, 2, TRUE);
	offset += 2;

	/* lock count */
	proto_tree_add_item(tree, hf_smb_count, tvb, offset, 4, TRUE);
	offset += 4;

	/* offset */
	proto_tree_add_item(tree, hf_smb_offset, tvb, offset, 4, TRUE);
	offset += 4;

	BYTE_COUNT;

	END_OF_SMB

	return offset;
}

static int
dissect_create_temporary_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	int fn_len;
	const char *fn;
	guint8 wc;
	guint16 bc;

	WORD_COUNT;

	/* 2 reserved bytes */
	proto_tree_add_item(tree, hf_smb_reserved, tvb, offset, 2, TRUE);
	offset += 2;

	/* Creation time */
	offset = dissect_smb_UTIME(tvb, pinfo, tree, offset, hf_smb_create_time);

	BYTE_COUNT;

	/* buffer format */
	proto_tree_add_item(tree, hf_smb_buffer_format, tvb, offset, 1, TRUE);
	offset += 1;

	/* directory name */
	fn = get_unicode_or_ascii_string_tvb(tvb, &offset, pinfo, &fn_len, FALSE, FALSE);
	proto_tree_add_string(tree, hf_smb_dir_name, tvb, offset, fn_len,
		fn);
	offset += fn_len;

	if (check_col(pinfo->fd, COL_INFO)) {
		col_append_fstr(pinfo->fd, COL_INFO, ", Path: %s", fn);
	}

	END_OF_SMB

	return offset;
}

static int
dissect_create_temporary_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	int fn_len;
	const char *fn;
	guint8 wc;
	guint16 bc;

	WORD_COUNT;

	/* fid */
	proto_tree_add_item(tree, hf_smb_fid, tvb, offset, 2, TRUE);
	offset += 2;

	BYTE_COUNT;

	/* buffer format */
	proto_tree_add_item(tree, hf_smb_buffer_format, tvb, offset, 1, TRUE);
	offset += 1;

	/* file name */
	fn = get_unicode_or_ascii_string_tvb(tvb, &offset, pinfo, &fn_len, FALSE, FALSE);
	proto_tree_add_string(tree, hf_smb_file_name, tvb, offset, fn_len,
		fn);
	offset += fn_len;

	END_OF_SMB

	return offset;
}

static const value_string seek_mode_vals[] = {
	{0,	"From Start Of File"},
	{1,	"From Current Position"},
	{2,	"From End Of File"},
	{0,	NULL}
};

static int
dissect_seek_file_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	guint8 wc;
	guint16 bc;

	WORD_COUNT;

	/* fid */
	proto_tree_add_item(tree, hf_smb_fid, tvb, offset, 2, TRUE);
	offset += 2;

	/* Seek Mode */
	proto_tree_add_item(tree, hf_smb_seek_mode, tvb, offset, 2, TRUE);
	offset += 2;

	/* offset */
	proto_tree_add_item(tree, hf_smb_offset, tvb, offset, 4, TRUE);
	offset += 4;

	BYTE_COUNT;

	END_OF_SMB

	return offset;
}

static int
dissect_seek_file_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	guint8 wc;
	guint16 bc;

	WORD_COUNT;

	/* offset */
	proto_tree_add_item(tree, hf_smb_offset, tvb, offset, 4, TRUE);
	offset += 4;

	BYTE_COUNT;

	END_OF_SMB

	return offset;
}
 
static int
dissect_set_information2_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	guint8 wc;
	guint16 bc;

	WORD_COUNT;

	/* fid */
	proto_tree_add_item(tree, hf_smb_fid, tvb, offset, 2, TRUE);
	offset += 2;

	/* create time */
	offset = dissect_smb_datetime(tvb, pinfo, tree, offset,
		hf_smb_create_time,
		hf_smb_create_dos_date, hf_smb_create_dos_time, FALSE);

	/* access time */
	offset = dissect_smb_datetime(tvb, pinfo, tree, offset,
		hf_smb_access_time,
		hf_smb_access_dos_date, hf_smb_access_dos_time, FALSE);

	/* last write time */
	offset = dissect_smb_datetime(tvb, pinfo, tree, offset,
		hf_smb_last_write_date,
		hf_smb_last_write_dos_date, hf_smb_last_write_dos_time, FALSE);

	BYTE_COUNT;

	END_OF_SMB

	return offset;
}

static int
dissect_query_information2_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	guint8 wc;
	guint16 bc;

	WORD_COUNT;

	/* create time */
	offset = dissect_smb_datetime(tvb, pinfo, tree, offset,
		hf_smb_create_time,
		hf_smb_create_dos_date, hf_smb_create_dos_time, FALSE);

	/* access time */
	offset = dissect_smb_datetime(tvb, pinfo, tree, offset,
		hf_smb_access_time,
		hf_smb_access_dos_date, hf_smb_access_dos_time, FALSE);

	/* last write time */
	offset = dissect_smb_datetime(tvb, pinfo, tree, offset,
		hf_smb_last_write_date,
		hf_smb_last_write_dos_date, hf_smb_last_write_dos_time, FALSE);

	/* data size */
	proto_tree_add_item(tree, hf_smb_data_size, tvb, offset, 4, TRUE);
	offset += 4;

	/* allocation size */
	proto_tree_add_item(tree, hf_smb_alloc_size, tvb, offset, 4, TRUE);
	offset += 4;

	/* File Attributes */
	offset = dissect_file_attributes(tvb, pinfo, tree, offset);

	BYTE_COUNT;

	END_OF_SMB

	return offset;
}
 

static int
dissect_write_and_close_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	guint16 cnt;
	guint8 wc;
	guint16 bc;

	WORD_COUNT;

	/* write count */
	cnt = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint(tree, hf_smb_count, tvb, offset, 2, cnt);
	offset += 2;

	BYTE_COUNT;

	END_OF_SMB

	return offset;
}

static int
dissect_write_and_close_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	guint8 wc;
	guint16 cnt=0;
	guint16 bc;

	WORD_COUNT;

	/* fid */
	proto_tree_add_item(tree, hf_smb_fid, tvb, offset, 2, TRUE);
	offset += 2;

	/* write count */
	cnt = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint(tree, hf_smb_count, tvb, offset, 2, cnt);
	offset += 2;

	/* offset */
	proto_tree_add_item(tree, hf_smb_offset, tvb, offset, 4, TRUE);
	offset += 4;

	/* last write time */
	offset = dissect_smb_UTIME(tvb, pinfo, tree, offset, hf_smb_last_write_time);
	
	if(wc==12){
		/* 12 reserved bytes */
		proto_tree_add_item(tree, hf_smb_reserved, tvb, offset, 12, TRUE);
		offset += 12;
	}

	BYTE_COUNT;

	/* 1 pad byte */
	proto_tree_add_bytes(tree, hf_smb_padding, tvb, offset, 1,
		tvb_get_ptr(tvb, offset, 1));
	offset += 1;
	
	/*XXX Do we have to do something like in dissect_read_file_response()?
	      Must check some captures. */
	/* file data */
	if(cnt>tvb_length_remaining(tvb, offset)){
		int len;
		len = tvb_length_remaining(tvb, offset);
		proto_tree_add_bytes_format(tree, hf_smb_file_data, tvb, offset, len, tvb_get_ptr(tvb, offset, len),"Incomplete data. Only %d of %d bytes", len, cnt);
		offset += len;
	} else {
		proto_tree_add_item(tree, hf_smb_file_data, tvb, offset, cnt, TRUE);
		offset += cnt;
	}

	END_OF_SMB

	return offset;
}
 
static int
dissect_read_raw_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	guint8 wc;
	guint16 bc;
	guint32 to;

	WORD_COUNT;

	/* fid */
	proto_tree_add_item(tree, hf_smb_fid, tvb, offset, 2, TRUE);
	offset += 2;

	/* offset */
	proto_tree_add_item(tree, hf_smb_offset, tvb, offset, 4, TRUE);
	offset += 4;

	/* max count */
	proto_tree_add_item(tree, hf_smb_max_count, tvb, offset, 2, TRUE);
	offset += 2;

	/* min count */
	proto_tree_add_item(tree, hf_smb_min_count, tvb, offset, 2, TRUE);
	offset += 2;

	/* timeout */
	to = tvb_get_letohl(tvb, offset);
	proto_tree_add_uint_format(tree, hf_smb_timeout, tvb, offset, 4, to, "Timeout: %s", time_msecs_to_str(to));
	offset += 4;

	/* 2 reserved bytes */
	proto_tree_add_item(tree, hf_smb_reserved, tvb, offset, 2, TRUE);
	offset += 2;

	if(wc==10){
		/* high offset */
		proto_tree_add_item(tree, hf_smb_high_offset, tvb, offset, 4, TRUE);
		offset += 4;
	}

	BYTE_COUNT;

	END_OF_SMB

	return offset;
}

static int
dissect_query_information_disk_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree)
{
	guint8 wc;
	guint16 bc;

	WORD_COUNT;

	/* units */
	proto_tree_add_item(tree, hf_smb_units, tvb, offset, 2, TRUE);
	offset += 2;

	/* bpu */
	proto_tree_add_item(tree, hf_smb_bpu, tvb, offset, 2, TRUE);
	offset += 2;

	/* block size */
	proto_tree_add_item(tree, hf_smb_blocksize, tvb, offset, 2, TRUE);
	offset += 2;

	/* free units */
	proto_tree_add_item(tree, hf_smb_freeunits, tvb, offset, 2, TRUE);
	offset += 2;

	/* 2 reserved bytes */
	proto_tree_add_item(tree, hf_smb_reserved, tvb, offset, 2, TRUE);
	offset += 2;

	BYTE_COUNT;

	END_OF_SMB

	return offset;
}




typedef struct _smb_function {
       int (*request)(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree);
       int (*response)(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree);
} smb_function;

smb_function smb_dissector[256] = {
  /* 0x00 Create Dir*/  {dissect_old_dir_request, dissect_empty},
  /* 0x01 Delete Dir*/  {dissect_old_dir_request, dissect_empty},
  /* 0x02 Open File*/  {dissect_open_file_request, dissect_open_file_response},
  /* 0x03 Create File*/  {dissect_create_file_request, dissect_fid},
  /* 0x04 Close File*/  {dissect_close_file_request, dissect_empty},
  /* 0x05 Flush File*/  {dissect_fid, dissect_empty},
  /* 0x06 Delete File*/  {dissect_delete_file_request, dissect_empty},
  /* 0x07 Rename File*/  {dissect_rename_file_request, dissect_empty},
  /* 0x08 Query Info*/  {dissect_query_information_request, dissect_query_information_response},
  /* 0x09 Set Info*/  {dissect_set_information_request, dissect_empty},
  /* 0x0a Read File*/  {dissect_read_file_request, dissect_read_file_response},
  /* 0x0b Write File*/  {dissect_write_file_request, dissect_write_file_response},
  /* 0x0c Lock Byte Range*/  {dissect_lock_request, dissect_empty},
  /* 0x0d Unlock Byte Range*/  {dissect_lock_request, dissect_empty},
  /* 0x0e Create Temp*/  {dissect_create_temporary_request, dissect_create_temporary_response},
  /* 0x0f Create New*/  {dissect_create_file_request, dissect_fid},
  /* 0x10 Check Dir*/  {dissect_old_dir_request, dissect_empty},
  /* 0x11 Process Exit*/  {dissect_empty, dissect_empty},
  /* 0x12 Seek File*/  {dissect_seek_file_request, dissect_seek_file_response},
  /* 0x13 Lock And Read*/  {dissect_read_file_request, dissect_lock_and_read_response},
  /* 0x14 Write And Unlock*/  {dissect_write_file_request, dissect_write_file_response},
  /* 0x15 */  {NULL, NULL},
  /* 0x16 */  {NULL, NULL},
  /* 0x17 */  {NULL, NULL},
  /* 0x18 */  {NULL, NULL},
  /* 0x19 */  {NULL, NULL},
  /* 0x1a Read Raw*/  {dissect_read_raw_request, NULL},
  /* 0x1b */  {NULL, NULL},
  /* 0x1c */  {NULL, NULL},
  /* 0x1d */  {NULL, NULL},
  /* 0x1e */  {NULL, NULL},
  /* 0x1f */  {NULL, NULL},
  /* 0x20 Write Complete*/  {NULL, dissect_write_and_close_response},
  /* 0x21 */  {NULL, NULL},
  /* 0x22 Set Info2*/  {dissect_set_information2_request, dissect_empty},
  /* 0x23 Query Info2*/  {dissect_fid, dissect_query_information2_response},
  /* 0x24 */  {NULL, NULL},
  /* 0x25 */  {NULL, NULL},
  /* 0x26 */  {NULL, NULL},
  /* 0x27 */  {NULL, NULL},
  /* 0x28 */  {NULL, NULL},
  /* 0x29 */  {NULL, NULL},
  /* 0x2a Move File*/  {dissect_move_request, dissect_move_response},
  /* 0x2b Echo*/  {dissect_echo_request, dissect_echo_response},
  /* 0x2c Write And Close*/  {dissect_write_and_close_request, dissect_write_and_close_response},
  /* 0x2d */  {NULL, NULL},
  /* 0x2e */  {NULL, NULL},
  /* 0x2f */  {NULL, NULL},
  /* 0x30 */  {NULL, NULL},
  /* 0x31 */  {NULL, NULL},
  /* 0x32 */  {NULL, NULL},
  /* 0x33 */  {NULL, NULL},
  /* 0x34 */  {NULL, NULL},
  /* 0x35 */  {NULL, NULL},
  /* 0x36 */  {NULL, NULL},
  /* 0x37 */  {NULL, NULL},
  /* 0x38 */  {NULL, NULL},
  /* 0x39 */  {NULL, NULL},
  /* 0x3a */  {NULL, NULL},
  /* 0x3b */  {NULL, NULL},
  /* 0x3c */  {NULL, NULL},
  /* 0x3d */  {NULL, NULL},
  /* 0x3e */  {NULL, NULL},
  /* 0x3f */  {NULL, NULL},
  /* 0x40 */  {NULL, NULL},
  /* 0x41 */  {NULL, NULL},
  /* 0x42 */  {NULL, NULL},
  /* 0x43 */  {NULL, NULL},
  /* 0x44 */  {NULL, NULL},
  /* 0x45 */  {NULL, NULL},
  /* 0x46 */  {NULL, NULL},
  /* 0x47 */  {NULL, NULL},
  /* 0x48 */  {NULL, NULL},
  /* 0x49 */  {NULL, NULL},
  /* 0x4a */  {NULL, NULL},
  /* 0x4b */  {NULL, NULL},
  /* 0x4c */  {NULL, NULL},
  /* 0x4d */  {NULL, NULL},
  /* 0x4e */  {NULL, NULL},
  /* 0x4f */  {NULL, NULL},
  /* 0x50 */  {NULL, NULL},
  /* 0x51 */  {NULL, NULL},
  /* 0x52 */  {NULL, NULL},
  /* 0x53 */  {NULL, NULL},
  /* 0x54 */  {NULL, NULL},
  /* 0x55 */  {NULL, NULL},
  /* 0x56 */  {NULL, NULL},
  /* 0x57 */  {NULL, NULL},
  /* 0x58 */  {NULL, NULL},
  /* 0x59 */  {NULL, NULL},
  /* 0x5a */  {NULL, NULL},
  /* 0x5b */  {NULL, NULL},
  /* 0x5c */  {NULL, NULL},
  /* 0x5d */  {NULL, NULL},
  /* 0x5e */  {NULL, NULL},
  /* 0x5f */  {NULL, NULL},
  /* 0x60 */  {NULL, NULL},
  /* 0x61 */  {NULL, NULL},
  /* 0x62 */  {NULL, NULL},
  /* 0x63 */  {NULL, NULL},
  /* 0x64 */  {NULL, NULL},
  /* 0x65 */  {NULL, NULL},
  /* 0x66 */  {NULL, NULL},
  /* 0x67 */  {NULL, NULL},
  /* 0x68 */  {NULL, NULL},
  /* 0x69 */  {NULL, NULL},
  /* 0x6a */  {NULL, NULL},
  /* 0x6b */  {NULL, NULL},
  /* 0x6c */  {NULL, NULL},
  /* 0x6d */  {NULL, NULL},
  /* 0x6e */  {NULL, NULL},
  /* 0x6f */  {NULL, NULL},
  /* 0x70 Tree Connect*/  {dissect_tree_connect_request, dissect_tree_connect_response},
  /* 0x71 Tree Disconnect*/  {dissect_empty, dissect_empty},
  /* 0x72 Negotiate Protocol*/	{dissect_negprot_request, dissect_negprot_response},
  /* 0x73 */  {NULL, NULL},
  /* 0x74 */  {NULL, NULL},
  /* 0x75 */  {NULL, NULL},
  /* 0x76 */  {NULL, NULL},
  /* 0x77 */  {NULL, NULL},
  /* 0x78 */  {NULL, NULL},
  /* 0x79 */  {NULL, NULL},
  /* 0x7a */  {NULL, NULL},
  /* 0x7b */  {NULL, NULL},
  /* 0x7c */  {NULL, NULL},
  /* 0x7d */  {NULL, NULL},
  /* 0x7e */  {NULL, NULL},
  /* 0x7f */  {NULL, NULL},
  /* 0x80 Query Info Disk*/  {dissect_empty, dissect_query_information_disk_response},
  /* 0x81 */  {NULL, NULL},
  /* 0x82 */  {NULL, NULL},
  /* 0x83 */  {NULL, NULL},
  /* 0x84 */  {NULL, NULL},
  /* 0x85 */  {NULL, NULL},
  /* 0x86 */  {NULL, NULL},
  /* 0x87 */  {NULL, NULL},
  /* 0x88 */  {NULL, NULL},
  /* 0x89 */  {NULL, NULL},
  /* 0x8a */  {NULL, NULL},
  /* 0x8b */  {NULL, NULL},
  /* 0x8c */  {NULL, NULL},
  /* 0x8d */  {NULL, NULL},
  /* 0x8e */  {NULL, NULL},
  /* 0x8f */  {NULL, NULL},
  /* 0x90 */  {NULL, NULL},
  /* 0x91 */  {NULL, NULL},
  /* 0x92 */  {NULL, NULL},
  /* 0x93 */  {NULL, NULL},
  /* 0x94 */  {NULL, NULL},
  /* 0x95 */  {NULL, NULL},
  /* 0x96 */  {NULL, NULL},
  /* 0x97 */  {NULL, NULL},
  /* 0x98 */  {NULL, NULL},
  /* 0x99 */  {NULL, NULL},
  /* 0x9a */  {NULL, NULL},
  /* 0x9b */  {NULL, NULL},
  /* 0x9c */  {NULL, NULL},
  /* 0x9d */  {NULL, NULL},
  /* 0x9e */  {NULL, NULL},
  /* 0x9f */  {NULL, NULL},
  /* 0xa0 */  {NULL, NULL},
  /* 0xa1 */  {NULL, NULL},
  /* 0xa2 */  {NULL, NULL},
  /* 0xa3 */  {NULL, NULL},
  /* 0xa4 */  {NULL, NULL},
  /* 0xa5 */  {NULL, NULL},
  /* 0xa6 */  {NULL, NULL},
  /* 0xa7 */  {NULL, NULL},
  /* 0xa8 */  {NULL, NULL},
  /* 0xa9 */  {NULL, NULL},
  /* 0xaa */  {NULL, NULL},
  /* 0xab */  {NULL, NULL},
  /* 0xac */  {NULL, NULL},
  /* 0xad */  {NULL, NULL},
  /* 0xae */  {NULL, NULL},
  /* 0xaf */  {NULL, NULL},
  /* 0xb0 */  {NULL, NULL},
  /* 0xb1 */  {NULL, NULL},
  /* 0xb2 */  {NULL, NULL},
  /* 0xb3 */  {NULL, NULL},
  /* 0xb4 */  {NULL, NULL},
  /* 0xb5 */  {NULL, NULL},
  /* 0xb6 */  {NULL, NULL},
  /* 0xb7 */  {NULL, NULL},
  /* 0xb8 */  {NULL, NULL},
  /* 0xb9 */  {NULL, NULL},
  /* 0xba */  {NULL, NULL},
  /* 0xbb */  {NULL, NULL},
  /* 0xbc */  {NULL, NULL},
  /* 0xbd */  {NULL, NULL},
  /* 0xbe */  {NULL, NULL},
  /* 0xbf */  {NULL, NULL},
  /* 0xc0 */  {NULL, NULL},
  /* 0xc1 */  {NULL, NULL},
  /* 0xc2 Close Print File*/  {dissect_fid, dissect_empty},
  /* 0xc3 */  {NULL, NULL},
  /* 0xc4 */  {NULL, NULL},
  /* 0xc5 */  {NULL, NULL},
  /* 0xc6 */  {NULL, NULL},
  /* 0xc7 */  {NULL, NULL},
  /* 0xc8 */  {NULL, NULL},
  /* 0xc9 */  {NULL, NULL},
  /* 0xca */  {NULL, NULL},
  /* 0xcb */  {NULL, NULL},
  /* 0xcc */  {NULL, NULL},
  /* 0xcd */  {NULL, NULL},
  /* 0xce */  {NULL, NULL},
  /* 0xcf */  {NULL, NULL},
  /* 0xd0 */  {NULL, NULL},
  /* 0xd1 */  {NULL, NULL},
  /* 0xd2 */  {NULL, NULL},
  /* 0xd3 */  {NULL, NULL},
  /* 0xd4 */  {NULL, NULL},
  /* 0xd5 */  {NULL, NULL},
  /* 0xd6 */  {NULL, NULL},
  /* 0xd7 */  {NULL, NULL},
  /* 0xd8 */  {NULL, NULL},
  /* 0xd9 */  {NULL, NULL},
  /* 0xda */  {NULL, NULL},
  /* 0xdb */  {NULL, NULL},
  /* 0xdc */  {NULL, NULL},
  /* 0xdd */  {NULL, NULL},
  /* 0xde */  {NULL, NULL},
  /* 0xdf */  {NULL, NULL},
  /* 0xe0 */  {NULL, NULL},
  /* 0xe1 */  {NULL, NULL},
  /* 0xe2 */  {NULL, NULL},
  /* 0xe3 */  {NULL, NULL},
  /* 0xe4 */  {NULL, NULL},
  /* 0xe5 */  {NULL, NULL},
  /* 0xe6 */  {NULL, NULL},
  /* 0xe7 */  {NULL, NULL},
  /* 0xe8 */  {NULL, NULL},
  /* 0xe9 */  {NULL, NULL},
  /* 0xea */  {NULL, NULL},
  /* 0xeb */  {NULL, NULL},
  /* 0xec */  {NULL, NULL},
  /* 0xed */  {NULL, NULL},
  /* 0xee */  {NULL, NULL},
  /* 0xef */  {NULL, NULL},
  /* 0xf0 */  {NULL, NULL},
  /* 0xf1 */  {NULL, NULL},
  /* 0xf2 */  {NULL, NULL},
  /* 0xf3 */  {NULL, NULL},
  /* 0xf4 */  {NULL, NULL},
  /* 0xf5 */  {NULL, NULL},
  /* 0xf6 */  {NULL, NULL},
  /* 0xf7 */  {NULL, NULL},
  /* 0xf8 */  {NULL, NULL},
  /* 0xf9 */  {NULL, NULL},
  /* 0xfa */  {NULL, NULL},
  /* 0xfb */  {NULL, NULL},
  /* 0xfc */  {NULL, NULL},
  /* 0xfd */  {NULL, NULL},
  /* 0xfe */  {NULL, NULL},
  /* 0xff */  {NULL, NULL},
};

static int
dissect_smb_command(tvbuff_t *tvb, packet_info *pinfo, proto_tree *top_tree, int offset, proto_tree *smb_tree, guint8 cmd)
{
	int old_offset = offset;
	smb_info_t *si;
 
	si = pinfo->private_data;
	if(cmd!=0xff){
		proto_item *cmd_item;
		proto_tree *cmd_tree;
		int (*dissector)(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree);

		if (check_col(pinfo->fd, COL_INFO)) {
			col_add_fstr(pinfo->fd, COL_INFO, "%s %s",
				decode_smb_name(cmd),
				(si->request)? "Request" : "Response");
		}

		cmd_item = proto_tree_add_text(smb_tree, tvb, offset,
			0, "%s %s (0x%02x)",
			decode_smb_name(cmd), 
			(si->request)?"Request":"Response",
			cmd);

		cmd_tree = proto_item_add_subtree(cmd_item, ett_smb_command);

		dissector = (si->request)?
			smb_dissector[cmd].request:smb_dissector[cmd].response;

		if(dissector){
			offset = (*dissector)(tvb, pinfo, cmd_tree, offset, smb_tree);
		}
		proto_item_set_len(cmd_item, offset-old_offset);
	}
	return offset;
}


/* NOTE: this value_string array will also be used to access data directly by
 * index instead of val_to_str() since 
 * 1, the array will always span every value from 0x00 to 0xff and
 * 2, smb_cmd_vals[i].strptr  is much cheaper than  val_to_str(i, smb_cmd_vals,)
 * This means that this value_string array MUST always
 * 1, contain all entries 0x00 to 0xff
 * 2, all entries must be in order.
 */
static const value_string smb_cmd_vals[] = {
  { 0x00, "Create Directory" },
  { 0x01, "Delete Directory" },
  { 0x02, "Open" },
  { 0x03, "Create" },
  { 0x04, "Close" },
  { 0x05, "Flush" },
  { 0x06, "Delete" },
  { 0x07, "Rename" },
  { 0x08, "Query Information" },
  { 0x09, "Set Information" },
  { 0x0A, "Read" },
  { 0x0B, "Write" },
  { 0x0C, "Lock Byte Range" },
  { 0x0D, "Unlock Byte Range" },
  { 0x0E, "Create Temp" },
  { 0x0F, "Create New" },
  { 0x10, "Check Directory" },
  { 0x11, "Process Exit" },
  { 0x12, "Seek" },
  { 0x13, "Lock And Read" },
  { 0x14, "Write And Unlock" },
  { 0x15, "unknown-0x15" },
  { 0x16, "unknown-0x16" },
  { 0x17, "unknown-0x17" },
  { 0x18, "unknown-0x18" },
  { 0x19, "unknown-0x19" },
  { 0x1A, "Read Raw" },
  { 0x1B, "Read MPX" },
  { 0x1C, "Read MPX Secondary" },
  { 0x1D, "Write Raw" },
  { 0x1E, "Write MPX" },
  { 0x1F, "SMBwriteBs" },
  { 0x20, "Write Complete" },
  { 0x21, "unknown-0x21" },
  { 0x22, "Set Information2" },
  { 0x23, "Query Information2" },
  { 0x24, "Locking AndX" },
  { 0x25, "Transaction" },
  { 0x26, "Transaction Secondary" },
  { 0x27, "IOCTL" },
  { 0x28, "IOCTL Secondary" },
  { 0x29, "Copy" },
  { 0x2A, "Move" },
  { 0x2B, "Echo" },
  { 0x2C, "Write And Close" },
  { 0x2D, "Open AndX" },
  { 0x2E, "Read AndX" },
  { 0x2F, "Write AndX" },
  { 0x30, "unknown-0x30" },
  { 0x31, "Close And Tree Discover" },
  { 0x32, "Transaction2" },
  { 0x33, "Transaction2 Secondary" },
  { 0x34, "Find Close2" },
  { 0x35, "Find Notify Close" },
  { 0x36, "unknown-0x36" },
  { 0x37, "unknown-0x37" },
  { 0x38, "unknown-0x38" },
  { 0x39, "unknown-0x39" },
  { 0x3A, "unknown-0x3A" },
  { 0x3B, "unknown-0x3B" },
  { 0x3C, "unknown-0x3C" },
  { 0x3D, "unknown-0x3D" },
  { 0x3E, "unknown-0x3E" },
  { 0x3F, "unknown-0x3F" },
  { 0x40, "unknown-0x40" },
  { 0x41, "unknown-0x41" },
  { 0x42, "unknown-0x42" },
  { 0x43, "unknown-0x43" },
  { 0x44, "unknown-0x44" },
  { 0x45, "unknown-0x45" },
  { 0x46, "unknown-0x46" },
  { 0x47, "unknown-0x47" },
  { 0x48, "unknown-0x48" },
  { 0x49, "unknown-0x49" },
  { 0x4A, "unknown-0x4A" },
  { 0x4B, "unknown-0x4B" },
  { 0x4C, "unknown-0x4C" },
  { 0x4D, "unknown-0x4D" },
  { 0x4E, "unknown-0x4E" },
  { 0x4F, "unknown-0x4F" },
  { 0x50, "unknown-0x50" },
  { 0x51, "unknown-0x51" },
  { 0x52, "unknown-0x52" },
  { 0x53, "unknown-0x53" },
  { 0x54, "unknown-0x54" },
  { 0x55, "unknown-0x55" },
  { 0x56, "unknown-0x56" },
  { 0x57, "unknown-0x57" },
  { 0x58, "unknown-0x58" },
  { 0x59, "unknown-0x59" },
  { 0x5A, "unknown-0x5A" },
  { 0x5B, "unknown-0x5B" },
  { 0x5C, "unknown-0x5C" },
  { 0x5D, "unknown-0x5D" },
  { 0x5E, "unknown-0x5E" },
  { 0x5F, "unknown-0x5F" },
  { 0x60, "unknown-0x60" },
  { 0x61, "unknown-0x61" },
  { 0x62, "unknown-0x62" },
  { 0x63, "unknown-0x63" },
  { 0x64, "unknown-0x64" },
  { 0x65, "unknown-0x65" },
  { 0x66, "unknown-0x66" },
  { 0x67, "unknown-0x67" },
  { 0x68, "unknown-0x68" },
  { 0x69, "unknown-0x69" },
  { 0x6A, "unknown-0x6A" },
  { 0x6B, "unknown-0x6B" },
  { 0x6C, "unknown-0x6C" },
  { 0x6D, "unknown-0x6D" },
  { 0x6E, "unknown-0x6E" },
  { 0x6F, "unknown-0x6F" },
  { 0x70, "Tree Connect" },
  { 0x71, "Tree Disconnect" },
  { 0x72, "Negotiate Protocol" },
  { 0x73, "Session Setup AndX" },
  { 0x74, "Logoff AndX" },
  { 0x75, "Tree Connect AndX" },
  { 0x76, "unknown-0x76" },
  { 0x77, "unknown-0x77" },
  { 0x78, "unknown-0x78" },
  { 0x79, "unknown-0x79" },
  { 0x7A, "unknown-0x7A" },
  { 0x7B, "unknown-0x7B" },
  { 0x7C, "unknown-0x7C" },
  { 0x7D, "unknown-0x7D" },
  { 0x7E, "unknown-0x7E" },
  { 0x7F, "unknown-0x7F" },
  { 0x80, "Query Information Disk" },
  { 0x81, "Search" },
  { 0x82, "Find" },
  { 0x83, "Find Unique" },
  { 0x84, "SMBfclose" },
  { 0x85, "unknown-0x85" },
  { 0x86, "unknown-0x86" },
  { 0x87, "unknown-0x87" },
  { 0x88, "unknown-0x88" },
  { 0x89, "unknown-0x89" },
  { 0x8A, "unknown-0x8A" },
  { 0x8B, "unknown-0x8B" },
  { 0x8C, "unknown-0x8C" },
  { 0x8D, "unknown-0x8D" },
  { 0x8E, "unknown-0x8E" },
  { 0x8F, "unknown-0x8F" },
  { 0x90, "unknown-0x90" },
  { 0x91, "unknown-0x91" },
  { 0x92, "unknown-0x92" },
  { 0x93, "unknown-0x93" },
  { 0x94, "unknown-0x94" },
  { 0x95, "unknown-0x95" },
  { 0x96, "unknown-0x96" },
  { 0x97, "unknown-0x97" },
  { 0x98, "unknown-0x98" },
  { 0x99, "unknown-0x99" },
  { 0x9A, "unknown-0x9A" },
  { 0x9B, "unknown-0x9B" },
  { 0x9C, "unknown-0x9C" },
  { 0x9D, "unknown-0x9D" },
  { 0x9E, "unknown-0x9E" },
  { 0x9F, "unknown-0x9F" },
  { 0xA0, "NT Transact" },
  { 0xA1, "NT Transact Secondary" },
  { 0xA2, "NT Create AndX" },
  { 0xA3, "unknown-0xA3" },
  { 0xA4, "NT Cancel" },
  { 0xA5, "unknown-0xA5" },
  { 0xA6, "unknown-0xA6" },
  { 0xA7, "unknown-0xA7" },
  { 0xA8, "unknown-0xA8" },
  { 0xA9, "unknown-0xA9" },
  { 0xAA, "unknown-0xAA" },
  { 0xAB, "unknown-0xAB" },
  { 0xAC, "unknown-0xAC" },
  { 0xAD, "unknown-0xAD" },
  { 0xAE, "unknown-0xAE" },
  { 0xAF, "unknown-0xAF" },
  { 0xB0, "unknown-0xB0" },
  { 0xB1, "unknown-0xB1" },
  { 0xB2, "unknown-0xB2" },
  { 0xB3, "unknown-0xB3" },
  { 0xB4, "unknown-0xB4" },
  { 0xB5, "unknown-0xB5" },
  { 0xB6, "unknown-0xB6" },
  { 0xB7, "unknown-0xB7" },
  { 0xB8, "unknown-0xB8" },
  { 0xB9, "unknown-0xB9" },
  { 0xBA, "unknown-0xBA" },
  { 0xBB, "unknown-0xBB" },
  { 0xBC, "unknown-0xBC" },
  { 0xBD, "unknown-0xBD" },
  { 0xBE, "unknown-0xBE" },
  { 0xBF, "unknown-0xBF" },
  { 0xC0, "Open Print File" },
  { 0xC1, "Write Print File" },
  { 0xC2, "Close Print File" },
  { 0xC3, "Get Print Queue" },
  { 0xC4, "unknown-0xC4" },
  { 0xC5, "unknown-0xC5" },
  { 0xC6, "unknown-0xC6" },
  { 0xC7, "unknown-0xC7" },
  { 0xC8, "unknown-0xC8" },
  { 0xC9, "unknown-0xC9" },
  { 0xCA, "unknown-0xCA" },
  { 0xCB, "unknown-0xCB" },
  { 0xCC, "unknown-0xCC" },
  { 0xCD, "unknown-0xCD" },
  { 0xCE, "unknown-0xCE" },
  { 0xCF, "unknown-0xCF" },
  { 0xD0, "SMBsends" },
  { 0xD1, "SMBsendb" },
  { 0xD2, "SMBfwdname" },
  { 0xD3, "SMBcancelf" },
  { 0xD4, "SMBgetmac" },
  { 0xD5, "SMBsendstrt" },
  { 0xD6, "SMBsendend" },
  { 0xD7, "SMBsendtxt" },
  { 0xD8, "SMBreadbulk" },
  { 0xD9, "SMBwritebulk" },
  { 0xDA, "SMBwritebulkdata" },
  { 0xDB, "unknown-0xDB" },
  { 0xDC, "unknown-0xDC" },
  { 0xDD, "unknown-0xDD" },
  { 0xDE, "unknown-0xDE" },
  { 0xDF, "unknown-0xDF" },
  { 0xE0, "unknown-0xE0" },
  { 0xE1, "unknown-0xE1" },
  { 0xE2, "unknown-0xE2" },
  { 0xE3, "unknown-0xE3" },
  { 0xE4, "unknown-0xE4" },
  { 0xE5, "unknown-0xE5" },
  { 0xE6, "unknown-0xE6" },
  { 0xE7, "unknown-0xE7" },
  { 0xE8, "unknown-0xE8" },
  { 0xE9, "unknown-0xE9" },
  { 0xEA, "unknown-0xEA" },
  { 0xEB, "unknown-0xEB" },
  { 0xEC, "unknown-0xEC" },
  { 0xED, "unknown-0xED" },
  { 0xEE, "unknown-0xEE" },
  { 0xEF, "unknown-0xEF" },
  { 0xF0, "unknown-0xF0" },
  { 0xF1, "unknown-0xF1" },
  { 0xF2, "unknown-0xF2" },
  { 0xF3, "unknown-0xF3" },
  { 0xF4, "unknown-0xF4" },
  { 0xF5, "unknown-0xF5" },
  { 0xF6, "unknown-0xF6" },
  { 0xF7, "unknown-0xF7" },
  { 0xF8, "unknown-0xF8" },
  { 0xF9, "unknown-0xF9" },
  { 0xFA, "unknown-0xFA" },
  { 0xFB, "unknown-0xFB" },
  { 0xFC, "unknown-0xFC" },
  { 0xFD, "unknown-0xFD" },
  { 0xFE, "SMBinvalid" },
  { 0xFF, "unknown-0xFF" },
  { 0x00, NULL },
};

static char *decode_smb_name(unsigned char cmd)
{
  return(smb_cmd_vals[cmd].strptr);
}
 


/* XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
 * Everything TVBUFFIFIED above this line
 * XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX */


/*
 * Struct passed to each SMB decode routine of info it may need
 */


int smb_packet_init_count = 200;

/*
 * This is a hash table matching transaction requests and replies.
 *
 * Unfortunately, the MID is not a transaction ID in, say, the ONC RPC
 * sense; instead, it's a "multiplex ID" used when there's more than one
 * request *currently* in flight, to distinguish replies.
 *
 * This means that the MID and PID don't uniquely identify a request in
 * a conversation.
 *
 * Therefore, we have to use some other value to distinguish between
 * requests with the same MID and PID.
 *
 * On the first pass through the capture, when we first see a request,
 * we hash it by conversation, MID, and PID.
 *
 * When we first see a reply to it, we add it to a new hash table,
 * hashing it by conversation, MID, PID, and frame number of the reply.
 *
 * This works as long as
 *
 *	1) a client doesn't screw up and have multiple requests outstanding
 *	   with the same MID and PID
 *
 * and
 *
 *	2) we don't have, within the same frame, replies to multiple
 *	   requests with the same MID and PID.
 *
 * 2) should happen only if the server screws up and puts the wrong MID or
 * PID into a reply (in which case not only can we not handle this, the
 * client can't handle it either) or if the client has screwed up as per
 * 1) and the server's dutifully replied to both of the requests with the
 * same MID and PID (in which case, again, neither we nor the client can
 * handle this).
 *
 * We don't have to correctly dissect screwups; we just have to keep from
 * dumping core on them.
 *
 * XXX - in addition, we need to keep a hash table of replies, so that we
 * can associate continuations with the reply to which they're a continuation.
 */
struct smb_request_key {
  guint32 conversation;
  guint16 mid;
  guint16 pid;
  guint32 frame_num;
};

static GHashTable *smb_request_hash = NULL;
static GMemChunk *smb_request_keys = NULL;
static GMemChunk *smb_request_vals = NULL;

/*
 * This is a hash table matching continued transation replies and their
 * continuations.
 *
 * It works similarly to the request/reply hash table.
 */
static GHashTable *smb_continuation_hash = NULL;

static GMemChunk *smb_continuation_vals = NULL;

/* Hash Functions */
static gint
smb_equal(gconstpointer v, gconstpointer w)
{
  struct smb_request_key *v1 = (struct smb_request_key *)v;
  struct smb_request_key *v2 = (struct smb_request_key *)w;

#if defined(DEBUG_SMB_HASH)
  printf("Comparing %08X:%u:%u:%u\n      and %08X:%u:%u:%u\n",
	 v1 -> conversation, v1 -> mid, v1 -> pid, v1 -> frame_num,
	 v2 -> conversation, v2 -> mid, v2 -> pid, v2 -> frame_num);
#endif

  if (v1 -> conversation == v2 -> conversation &&
      v1 -> mid          == v2 -> mid &&
      v1 -> pid          == v2 -> pid &&
      v1 -> frame_num    == v2 -> frame_num) {

    return 1;

  }

  return 0;
}

static guint
smb_hash (gconstpointer v)
{
  struct smb_request_key *key = (struct smb_request_key *)v;
  guint val;

  val = (key -> conversation) + (key -> mid) + (key -> pid) +
	(key -> frame_num);

#if defined(DEBUG_SMB_HASH)
  printf("SMB Hash calculated as %u\n", val);
#endif

  return val;

}

/*
 * Free up any state information we've saved, and re-initialize the
 * tables of state information.
 */

/*
 * For a hash table entry, free the address data to which the key refers
 * and the fragment data to which the value refers.
 * (The actual key and value structures get freed by "reassemble_init()".)
 */
static gboolean
free_request_val_data(gpointer key, gpointer value, gpointer user_data)
{
  struct smb_request_val *request_val = value;

  if (request_val->last_transact_command != NULL)
    g_free(request_val->last_transact_command);
  if (request_val->last_param_descrip != NULL)
    g_free(request_val->last_param_descrip);
  if (request_val->last_data_descrip != NULL)
    g_free(request_val->last_data_descrip);
  if (request_val->last_aux_data_descrip != NULL)
    g_free(request_val->last_aux_data_descrip);
  return TRUE;
}

static struct smb_request_val *
do_transaction_hashing(conversation_t *conversation, struct smb_info si,
		       frame_data *fd)
{
  struct smb_request_key request_key, *new_request_key;
  struct smb_request_val *request_val = NULL;
  gpointer               new_request_key_ret, request_val_ret;

  if (si.request) {
    /*
     * This is a request.
     *
     * If this is the first time the frame has been seen, check for
     * an entry for the request in the hash table.  If it's not found,
     * insert an entry for it.
     *
     * If it's the first time it's been seen, then we can't have seen
     * the reply yet, so the reply frame number should be 0, for
     * "unknown".
     */
    if (!fd->flags.visited) {
      request_key.conversation = conversation->index;
      request_key.mid          = si.mid;
      request_key.pid          = si.pid;
      request_key.frame_num    = 0;

      request_val = (struct smb_request_val *) g_hash_table_lookup(smb_request_hash, &request_key);

      if (request_val == NULL) {
	/*
	 * Not found.
	 */
	new_request_key = g_mem_chunk_alloc(smb_request_keys);
	new_request_key -> conversation = conversation->index;
	new_request_key -> mid          = si.mid;
	new_request_key -> pid          = si.pid;
	new_request_key -> frame_num    = 0;

	request_val = g_mem_chunk_alloc(smb_request_vals);
	request_val -> frame = fd->num;
	request_val -> last_transact2_command = -1;		/* unknown */
	request_val -> last_transact_command = NULL;
	request_val -> last_param_descrip = NULL;
	request_val -> last_data_descrip = NULL;
	request_val -> last_aux_data_descrip = NULL;

	g_hash_table_insert(smb_request_hash, new_request_key, request_val);
      } else {
	/*
	 * This means that we've seen another request in this conversation
	 * with the same request and reply, and without an intervening
	 * reply to that first request, and thus won't be using this
	 * "request_val" structure for that request (as we'd use it only
	 * for the reply).
	 *
	 * Clean out the structure, and set it to refer to this frame.
	 */
	request_val -> frame = fd->num;
	request_val -> last_transact2_command = -1;		/* unknown */
	if (request_val -> last_transact_command)
	  g_free(request_val -> last_transact_command);
	request_val -> last_transact_command = NULL;
	if (request_val -> last_param_descrip)
	  g_free(request_val -> last_param_descrip);
	request_val -> last_param_descrip = NULL;
	if (request_val -> last_data_descrip)
	  g_free(request_val -> last_data_descrip);
	request_val -> last_data_descrip = NULL;
	if (request_val -> last_aux_data_descrip)
	  g_free(request_val -> last_aux_data_descrip);
	request_val -> last_aux_data_descrip = NULL;
      }
    }
  } else {
    /*
     * This is a reply.
     */
    if (!fd->flags.visited) {
      /*
       * This is the first time the frame has been seen; check for
       * an entry for a matching request, with an unknown reply frame
       * number, in the hash table.
       *
       * If we find it, re-hash it with this frame's number as the
       * reply frame number.
       */
      request_key.conversation = conversation->index;
      request_key.mid          = si.mid;
      request_key.pid          = si.pid;
      request_key.frame_num    = 0;

      /*
       * Look it up - and, if we find it, get pointers to the key and
       * value structures for it.
       */
      if (g_hash_table_lookup_extended(smb_request_hash, &request_key,
				       &new_request_key_ret,
				       &request_val_ret)) {
	new_request_key = new_request_key_ret;
	request_val = request_val_ret;

	/*
	 * We found it.
	 * Remove the old entry.
	 */
	g_hash_table_remove(smb_request_hash, &request_key);

	/*
	 * Now update the key, and put it back into the hash table with
	 * the new key.
	 */
	new_request_key->frame_num = fd->num;
	g_hash_table_insert(smb_request_hash, new_request_key, request_val);
      }
    } else {
      /*
       * This is not the first time the frame has been seen; check for
       * an entry for a matching request, with this frame's frame
       * number as the reply frame number, in the hash table.
       */
      request_key.conversation = conversation->index;
      request_key.mid          = si.mid;
      request_key.pid          = si.pid;
      request_key.frame_num    = fd->num;

      request_val = (struct smb_request_val *) g_hash_table_lookup(smb_request_hash, &request_key);
    }
  }

  return request_val;
}

static struct smb_continuation_val *
do_continuation_hashing(conversation_t *conversation, struct smb_info si,
		       frame_data *fd, guint16 TotalDataCount,
		       guint16 DataCount, const char **TransactName)
{
  struct smb_request_key request_key, *new_request_key;
  struct smb_continuation_val *continuation_val, *new_continuation_val;
  gpointer               new_request_key_ret, continuation_val_ret;

  continuation_val = NULL;
  if (si.ddisp != 0) {
    /*
     * This reply isn't the first in the series; there should be a
     * reply of which it is a continuation.
     */
    if (!fd->flags.visited) {
      /*
       * This is the first time the frame has been seen; check for
       * an entry for a matching continued message, with an unknown
       * continuation frame number, in the hash table.
       *
       * If we find it, re-hash it with this frame's number as the
       * continuation frame number.
       */
      request_key.conversation = conversation->index;
      request_key.mid          = si.mid;
      request_key.pid          = si.pid;
      request_key.frame_num    = 0;

      /*
       * Look it up - and, if we find it, get pointers to the key and
       * value structures for it.
       */
      if (g_hash_table_lookup_extended(smb_continuation_hash, &request_key,
				       &new_request_key_ret,
				       &continuation_val_ret)) {
	new_request_key = new_request_key_ret;
	continuation_val = continuation_val_ret;

	/*
	 * We found it.
	 * Remove the old entry.
	 */
	g_hash_table_remove(smb_continuation_hash, &request_key);

	/*
	 * Now update the key, and put it back into the hash table with
	 * the new key.
	 */
	new_request_key->frame_num = fd->num;
	g_hash_table_insert(smb_continuation_hash, new_request_key,
			    continuation_val);
      }
    } else {
      /*
       * This is not the first time the frame has been seen; check for
       * an entry for a matching request, with this frame's frame
       * number as the continuation frame number, in the hash table.
       */
      request_key.conversation = conversation->index;
      request_key.mid          = si.mid;
      request_key.pid          = si.pid;
      request_key.frame_num    = fd->num;

      continuation_val = (struct smb_continuation_val *)
		g_hash_table_lookup(smb_continuation_hash, &request_key);
    }
  }

  /*
   * If we found the entry for the message of which this is a continuation,
   * and our caller cares, get the transaction name for that message, as
   * it's the transaction name for this message as well.
   */
  if (continuation_val != NULL && TransactName != NULL)
    *TransactName = continuation_val -> transact_name;

  if (TotalDataCount > DataCount + si.ddisp) {
    /*
     * This reply isn't the last in the series; there should be a
     * continuation for it later in the capture.
     *
     * If this is the first time the frame has been seen, check for
     * an entry for the reply in the hash table.  If it's not found,
     * insert an entry for it.
     *
     * If it's the first time it's been seen, then we can't have seen
     * the continuation yet, so the continuation frame number should
     * be 0, for "unknown".
     */
    if (!fd->flags.visited) {
      request_key.conversation = conversation->index;
      request_key.mid          = si.mid;
      request_key.pid          = si.pid;
      request_key.frame_num    = 0;

      new_continuation_val = (struct smb_continuation_val *)
		g_hash_table_lookup(smb_continuation_hash, &request_key);

      if (new_continuation_val == NULL) {
	/*
	 * Not found.
	 */
	new_request_key = g_mem_chunk_alloc(smb_request_keys);
	new_request_key -> conversation = conversation->index;
	new_request_key -> mid          = si.mid;
	new_request_key -> pid          = si.pid;
	new_request_key -> frame_num    = 0;

	new_continuation_val = g_mem_chunk_alloc(smb_continuation_vals);
	new_continuation_val -> frame = fd->num;
	if (TransactName != NULL)
	  new_continuation_val -> transact_name = *TransactName;
	else
	  new_continuation_val -> transact_name = NULL;

	g_hash_table_insert(smb_continuation_hash, new_request_key,
			    new_continuation_val);
      } else {
	/*
	 * This presumably means we never saw the continuation of
	 * the message we found, and this is a reply to a different
	 * request; as we never saw the continuation of that message,
	 * we won't be using this "request_val" structure for that
	 * message (as we'd use it only for the continuation).
	 *
	 * Clean out the structure, and set it to refer to this frame.
	 */
	new_continuation_val -> frame = fd->num;
      }
    }
  }

  return continuation_val;
}

static void
smb_init_protocol(void)
{
#if defined(DEBUG_SMB_HASH)
  printf("Initializing SMB hashtable area\n");
#endif

  if (smb_request_hash) {
    /*
     * Remove all entries from the hash table and free all strings
     * attached to the keys and values.  (The keys and values
     * themselves are freed with "g_mem_chunk_destroy()" calls
     * below.)
     */
    g_hash_table_foreach_remove(smb_request_hash, free_request_val_data, NULL);
    g_hash_table_destroy(smb_request_hash);
  }
  if (smb_continuation_hash)
    g_hash_table_destroy(smb_continuation_hash);
  if (smb_request_keys)
    g_mem_chunk_destroy(smb_request_keys);
  if (smb_request_vals)
    g_mem_chunk_destroy(smb_request_vals);
  if (smb_continuation_vals)
    g_mem_chunk_destroy(smb_continuation_vals);

  smb_request_hash = g_hash_table_new(smb_hash, smb_equal);
  smb_continuation_hash = g_hash_table_new(smb_hash, smb_equal);
  smb_request_keys = g_mem_chunk_new("smb_request_keys",
				     sizeof(struct smb_request_key),
				     smb_packet_init_count * sizeof(struct smb_request_key), G_ALLOC_AND_FREE);
  smb_request_vals = g_mem_chunk_new("smb_request_vals",
				     sizeof(struct smb_request_val),
				     smb_packet_init_count * sizeof(struct smb_request_val), G_ALLOC_AND_FREE);
  smb_continuation_vals = g_mem_chunk_new("smb_continuation_vals",
				     sizeof(struct smb_continuation_val),
				     smb_packet_init_count * sizeof(struct smb_continuation_val), G_ALLOC_AND_FREE);
}

static void (*dissect[256])(const u_char *, int, frame_data *, proto_tree *, proto_tree *, struct smb_info si, int, int);

/*
 * XXX - global required to avoid changing the calling sequence of old-style
 * dissectors.
 */
static tvbuff_t *our_tvb;
static packet_info *our_pinfo;

static void
wrap_dissect_smb_command(proto_tree *top_tree, const guint8 *pd, int offset,
   proto_tree *smb_tree, guint8 cmd, struct smb_info *si, int max_data,
   int SMB_offset)
{
	if(smb_dissector[cmd].request){ 
	  /* call smb command dissector */
	  our_pinfo->private_data = si;
	  dissect_smb_command(our_tvb, our_pinfo, top_tree, offset, smb_tree, cmd);
	} else {
	  proto_item *cmd_item;
	  proto_tree *cmd_tree;

	  offset += SMB_offset;
	  if (check_col(our_pinfo->fd, COL_INFO)) {
	    col_add_fstr(our_pinfo->fd, COL_INFO, "%s %s",
			 decode_smb_name(cmd),
			 (si->request)? "Request" : "Response");
	  }

	  cmd_item = proto_tree_add_text(smb_tree, NullTVB, offset,
			0, "%s %s (0x%02x)",
			decode_smb_name(cmd), 
			(si->request)?"Request":"Response",
			cmd);
	  smb_tree = proto_item_add_subtree(cmd_item, ett_smb_command);

	  (dissect[cmd])(pd, offset, our_pinfo->fd, top_tree, smb_tree, *si,
			      max_data, SMB_offset);
	}
}

void 
dissect_unknown_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset)
{

  if (tree) {

    proto_tree_add_text(tree, NullTVB, offset, END_OF_FRAME, "Data (%u bytes)", 
			END_OF_FRAME); 

  }

}

/* 
 * Dissect a UNIX like date ...
 */

struct tm *_gtime; /* Add leading underscore ("_") to prevent symbol
                      conflict with /usr/include/time.h on some NetBSD
                      systems */

static char *
dissect_smbu_date(guint16 date, guint16 time)

{
  static char         datebuf[4+2+2+2+1+10];
  time_t              ltime = (date << 16) + time;

  _gtime = gmtime(&ltime);

  if (_gtime)
    sprintf(datebuf, "%04d-%02d-%02d",
	    1900 + (_gtime -> tm_year), 1 + (_gtime -> tm_mon), _gtime -> tm_mday);
  else 
    sprintf(datebuf, "Bad date format");

  return datebuf;

}

/*
 * Relies on time
 */
static char *
dissect_smbu_time(guint16 date, guint16 time)

{
  static char timebuf[2+2+2+2+1+10];

  if (_gtime)
    sprintf(timebuf, "%02d:%02d:%02d",
	    _gtime -> tm_hour, _gtime -> tm_min, _gtime -> tm_sec);
  else
    sprintf(timebuf, "Bad time format");

  return timebuf;

}

/* Max string length for displaying Unicode strings.  */
#define	MAX_UNICODE_STR_LEN	256

/* Turn a little-endian Unicode '\0'-terminated string into a string we
   can display.
   XXX - for now, we just handle the ISO 8859-1 characters. */
static gchar *
unicode_to_str(const guint8 *us, int *us_lenp) {
  static gchar  str[3][MAX_UNICODE_STR_LEN+3+1];
  static gchar *cur;
  gchar        *p;
  int           len;
  int           us_len;
  int           overflow = 0;

  NullTVB; /* remove this function when we are fully tvbuffified */
  if (cur == &str[0][0]) {
    cur = &str[1][0];
  } else if (cur == &str[1][0]) {  
    cur = &str[2][0];
  } else {  
    cur = &str[0][0];
  }
  p = cur;
  len = MAX_UNICODE_STR_LEN;
  us_len = 0;
  while (*us != 0 || *(us + 1) != 0) {
    if (len > 0) {
      *p++ = *us;
      len--;
    } else
      overflow = 1;
    us += 2;
    us_len += 2;
  }
  if (overflow) {
    /* Note that we're not showing the full string.  */
    *p++ = '.';
    *p++ = '.';
    *p++ = '.';
  }
  *p = '\0';
  *us_lenp = us_len;
  return cur;
}
/* Turn a little-endian Unicode '\0'-terminated string into a string we
   can display.
   XXX - for now, we just handle the ISO 8859-1 characters.
   If exactlen==TRUE then us_lenp contains the exact len of the string in
   bytes. It might not be null terminated !
*/
static gchar *
unicode_to_str_tvb(tvbuff_t *tvb, int offset, int *us_lenp, gboolean exactlen) {
  static gchar  str[3][MAX_UNICODE_STR_LEN+3+1];
  static gchar *cur;
  gchar        *p;
  guint16       uchar;
  int           len;
  int           us_len;
  int           overflow = 0;

  if (cur == &str[0][0]) {
    cur = &str[1][0];
  } else if (cur == &str[1][0]) {  
    cur = &str[2][0];
  } else {  
    cur = &str[0][0];
  }
  p = cur;
  len = MAX_UNICODE_STR_LEN;
  us_len = 0;
  while ((uchar = tvb_get_letohs(tvb, offset)) != 0) {
    if (len > 0) {
      if ((uchar & 0xFF00) == 0)
        *p++ = uchar;	/* ISO 8859-1 */
      else
        *p++ = '?';	/* not 8859-1 */
      len--;
    } else
      overflow = 1;
    offset += 2;
    us_len += 2;
    if(exactlen){
      if(us_len>= *us_lenp){
        break;
      }
    }
  }
  if (overflow) {
    /* Note that we're not showing the full string.  */
    *p++ = '.';
    *p++ = '.';
    *p++ = '.';
  }
  *p = '\0';
  *us_lenp = us_len;
  return cur;
}
 

/* Get a null terminated string, which is Unicode if "is_unicode" is true
   and ASCII (OEM character set) otherwise.
   XXX - for now, we just handle the ISO 8859-1 subset of Unicode. */
static const gchar *
get_unicode_or_ascii_string(const u_char *pd, int *offsetp, int SMB_offset,
    gboolean is_unicode, int *len)
{
  int offset = *offsetp;
  const gchar *string;
  int string_len;

  NullTVB;  /* delete this function when we are fully tvbuffified */
  if (is_unicode) {
    if ((offset - SMB_offset) % 2) {
      /*
       * XXX - this should be an offset relative to the beginning of the SMB,
       * not an offset relative to the beginning of the frame; if the stuff
       * before the SMB has an odd number of bytes, an offset relative to
       * the beginning of the frame will give the wrong answer.
       */
      offset++;   /* Looks like a pad byte there sometimes */
      *offsetp = offset;
    }
    string = unicode_to_str(pd + offset, &string_len);
    string_len += 2;
  } else {
    string = pd + offset;
    string_len = strlen(string) + 1;
  }
  *len = string_len;
  return string;
}

/* nopad == TRUE : Do not add any padding before this string
 * exactlen == TRUE : len contains the exact len of the string in bytes.
 */
static const gchar *
get_unicode_or_ascii_string_tvb(tvbuff_t *tvb, int *offsetp, packet_info *pinfo, int *len, gboolean nopad, gboolean exactlen)
{
  int offset = *offsetp;
  const gchar *string;
  int string_len;
  smb_info_t *si;

  si = pinfo->private_data;
  if (si->unicode) {
    if ((!nopad) && (*offsetp % 2)) {
      /*
       * XXX - this should be an offset relative to the beginning of the SMB,
       * not an offset relative to the beginning of the frame; if the stuff
       * before the SMB has an odd number of bytes, an offset relative to
       * the beginning of the frame will give the wrong answer.
       */
      (*offsetp)++;   /* Looks like a pad byte there sometimes */
    }
    if(exactlen){
      string_len = *len;
      string = unicode_to_str_tvb(tvb, *offsetp, &string_len, exactlen);
    } else {
      string = unicode_to_str_tvb(tvb, *offsetp, &string_len, exactlen);
      string_len += 2;
    }
  } else {
    if(exactlen){
      string = tvb_get_ptr(tvb, *offsetp, *len);
      string_len = *len;
    } else {
      string_len = tvb_strsize(tvb, *offsetp);
      string = tvb_get_ptr(tvb, *offsetp, string_len);
    }
  }
  *len = string_len;
  return string;
}


/*
 * Each dissect routine is passed an offset to wct and works from there 
 */


void
dissect_read_mpx_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *arent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset)

{
  guint8        WordCount;
  guint8        Pad;
  guint32       Reserved1;
  guint32       Offset;
  guint16       Reserved2;
  guint16       Reserved;
  guint16       MinCount;
  guint16       MaxCount;
  guint16       FID;
  guint16       DataOffset;
  guint16       DataLength;
  guint16       DataCompactionMode;
  guint16       Count;
  guint16       ByteCount;

  if (si.request) {
    /* Request(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    /* Build display for: FID */

    FID = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "FID: 0x%04x", FID);

    }

    offset += 2; /* Skip FID */

    /* Build display for: Offset */

    Offset = GWORD(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 4, "Offset: %u", Offset);

    }

    offset += 4; /* Skip Offset */

    /* Build display for: Max Count */

    MaxCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Max Count: %u", MaxCount);

    }

    offset += 2; /* Skip Max Count */

    /* Build display for: Min Count */

    MinCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Min Count: %u", MinCount);

    }

    offset += 2; /* Skip Min Count */

    /* Build display for: Reserved 1 */

    Reserved1 = GWORD(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 4, "Reserved 1: %u", Reserved1);

    }

    offset += 4; /* Skip Reserved 1 */

    /* Build display for: Reserved 2 */

    Reserved2 = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Reserved 2: %u", Reserved2);

    }

    offset += 2; /* Skip Reserved 2 */

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

  } else {
    /* Response(s) dissect code */

    /* Build display for: Word Count */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count */

    if (WordCount != 0) {

      /* Build display for: Offset */

      Offset = GWORD(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 4, "Offset: %u", Offset);

      }

      offset += 4; /* Skip Offset */

      /* Build display for: Count */

      Count = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Count: %u", Count);

      }

      offset += 2; /* Skip Count */

      /* Build display for: Reserved */

      Reserved = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Reserved: %u", Reserved);

      }

      offset += 2; /* Skip Reserved */

      /* Build display for: Data Compaction Mode */

      DataCompactionMode = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Data Compaction Mode: %u", DataCompactionMode);

      }

      offset += 2; /* Skip Data Compaction Mode */

      /* Build display for: Reserved */

      Reserved = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Reserved: %u", Reserved);

      }

      offset += 2; /* Skip Reserved */

      /* Build display for: Data Length */

      DataLength = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Data Length: %u", DataLength);

      }

      offset += 2; /* Skip Data Length */

      /* Build display for: Data Offset */

      DataOffset = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Data Offset: %u", DataOffset);

      }

      offset += 2; /* Skip Data Offset */

    }

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

    /* Build display for: Pad */

    Pad = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Pad: %u", Pad);

    }

    offset += 1; /* Skip Pad */

  }

}


/* Generated by build-dissect.pl Vesion 0.6 27-Jun-1999, ACT */
void
dissect_ssetup_andx_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset)

{
  proto_tree    *Capabilities_tree;
  proto_tree    *Action_tree;
  proto_item    *ti;
  guint8        WordCount;
  guint8        AndXReserved;
  guint8        AndXCommand = 0xFF;
  guint32       SessionKey;
  guint32       Reserved;
  guint32       Capabilities;
  guint16       VcNumber;
  guint16       SecurityBlobLength;
  guint16       ANSIAccountPasswordLength;
  guint16       UNICODEAccountPasswordLength;
  guint16       PasswordLen;
  guint16       MaxMpxCount;
  guint16       MaxBufferSize;
  guint16       ByteCount;
  guint16       AndXOffset = 0;
  guint16       Action;
  const char    *ANSIPassword;
  const char    *UNICODEPassword;
  const char    *SecurityBlob;
  const char    *Password;
  const char    *PrimaryDomain;
  const char    *NativeOS;
  const char    *NativeLanManType;
  const char    *NativeLanMan;
  const char    *AccountName;
  int           string_len;

  if (si.request) {
    /* Request(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    switch (WordCount) {

    case 10:

      /* Build display for: AndXCommand */

      AndXCommand = GBYTE(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 1, "AndXCommand: %s", 
			    (AndXCommand == 0xFF ? "No further commands" : decode_smb_name(AndXCommand)));

      }

      offset += 1; /* Skip AndXCommand */

      /* Build display for: AndXReserved */

      AndXReserved = GBYTE(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 1, "AndXReserved: %u", AndXReserved);

      }

      offset += 1; /* Skip AndXReserved */

      /* Build display for: AndXOffset */

      AndXOffset = GSHORT(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 2, "AndXOffset: %u", AndXOffset);

      }

      offset += 2; /* Skip AndXOffset */

      /* Build display for: MaxBufferSize */

      MaxBufferSize = GSHORT(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 2, "MaxBufferSize: %u", MaxBufferSize);

      }

      offset += 2; /* Skip MaxBufferSize */

      /* Build display for: MaxMpxCount */

      MaxMpxCount = GSHORT(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 2, "MaxMpxCount: %u", MaxMpxCount);

      }

      offset += 2; /* Skip MaxMpxCount */

      /* Build display for: VcNumber */

      VcNumber = GSHORT(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 2, "VcNumber: %u", VcNumber);

      }

      offset += 2; /* Skip VcNumber */

      /* Build display for: SessionKey */

      SessionKey = GWORD(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 4, "SessionKey: %u", SessionKey);

      }

      offset += 4; /* Skip SessionKey */

      /* Build display for: PasswordLen */

      PasswordLen = GSHORT(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 2, "PasswordLen: %u", PasswordLen);

      }

      offset += 2; /* Skip PasswordLen */

      /* Build display for: Reserved */

      Reserved = GWORD(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 4, "Reserved: %u", Reserved);

      }

      offset += 4; /* Skip Reserved */

      /* Build display for: Byte Count (BCC) */

      ByteCount = GSHORT(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

      }

      offset += 2; /* Skip Byte Count (BCC) */

      if (ByteCount > 0) {

 	/* Build display for: Password */

        Password = pd + offset;

	if (tree) {

	  proto_tree_add_text(tree, NullTVB, offset, strlen(Password) + 1, "Password: %s", Password);

	}

	offset += PasswordLen;

	/* Build display for: AccountName */

	AccountName = pd + offset;

	if (tree) {

	  proto_tree_add_text(tree, NullTVB, offset, strlen(AccountName) + 1, "AccountName: %s", AccountName);

	}

	offset += strlen(AccountName) + 1; /* Skip AccountName */

	/* Build display for: PrimaryDomain */

	PrimaryDomain = pd + offset;

	if (tree) {

	  proto_tree_add_text(tree, NullTVB, offset, strlen(PrimaryDomain) + 1, "PrimaryDomain: %s", PrimaryDomain);

	}

	offset += strlen(PrimaryDomain) + 1; /* Skip PrimaryDomain */

	/* Build display for: NativeOS */

	NativeOS = pd + offset;

	if (tree) {

	  proto_tree_add_text(tree, NullTVB, offset, strlen(NativeOS) + 1, "Native OS: %s", NativeOS);

	}

	offset += strlen(NativeOS) + 1; /* Skip NativeOS */

	/* Build display for: NativeLanMan */

	NativeLanMan = pd + offset;

	if (tree) {

	  proto_tree_add_text(tree, NullTVB, offset, strlen(NativeLanMan) + 1, "Native Lan Manager: %s", NativeLanMan);

	}

	offset += strlen(NativeLanMan) + 1; /* Skip NativeLanMan */

      }

      break;

    case 12:

      /* Build display for: AndXCommand */

      AndXCommand = GBYTE(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 1, "AndXCommand: %s", 
                            (AndXCommand == 0xFF ? "No further commands" : decode_smb_name(AndXCommand)));

      }

      offset += 1; /* Skip AndXCommand */

      /* Build display for: AndXReserved */

      AndXReserved = GBYTE(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 1, "AndXReserved: %u", AndXReserved);

      }

      offset += 1; /* Skip AndXReserved */

      /* Build display for: AndXOffset */

      AndXOffset = GSHORT(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 2, "AndXOffset: %u", AndXOffset);

      }

      offset += 2; /* Skip AndXOffset */

      /* Build display for: MaxBufferSize */

      MaxBufferSize = GSHORT(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 2, "MaxBufferSize: %u", MaxBufferSize);

      }

      offset += 2; /* Skip MaxBufferSize */

      /* Build display for: MaxMpxCount */

      MaxMpxCount = GSHORT(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 2, "MaxMpxCount: %u", MaxMpxCount);

      }

      offset += 2; /* Skip MaxMpxCount */

      /* Build display for: VcNumber */

      VcNumber = GSHORT(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 2, "VcNumber: %u", VcNumber);

      }

      offset += 2; /* Skip VcNumber */

      /* Build display for: SessionKey */

      SessionKey = GWORD(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 4, "SessionKey: %u", SessionKey);

      }

      offset += 4; /* Skip SessionKey */

      /* Build display for: Security Blob Length */

      SecurityBlobLength = GSHORT(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 2, "Security Blob Length: %u", SecurityBlobLength);

      }

      offset += 2; /* Skip Security Blob Length */

      /* Build display for: Reserved */

      Reserved = GWORD(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 4, "Reserved: %u", Reserved);

      }

      offset += 4; /* Skip Reserved */

      /* Build display for: Capabilities */

      Capabilities = GWORD(pd, offset);

      if (tree) {

        ti = proto_tree_add_text(tree, NullTVB, offset, 4, "Capabilities: 0x%08x", Capabilities);
        Capabilities_tree = proto_item_add_subtree(ti, ett_smb_capabilities);
        proto_tree_add_text(Capabilities_tree, NullTVB, offset, 4, "%s",
                            decode_boolean_bitfield(Capabilities, 0x0001, 32, " Raw Mode supported", " Raw Mode not supported"));
        proto_tree_add_text(Capabilities_tree, NullTVB, offset, 4, "%s",
                            decode_boolean_bitfield(Capabilities, 0x0002, 32, " Raw Mode supported", " MPX Mode not supported"));
        proto_tree_add_text(Capabilities_tree, NullTVB, offset, 4, "%s",
                            decode_boolean_bitfield(Capabilities, 0x0004, 32," Unicode supported", " Unicode not supported"));
        proto_tree_add_text(Capabilities_tree, NullTVB, offset, 4, "%s",
                            decode_boolean_bitfield(Capabilities, 0x0008, 32, " Large Files supported", " Large Files not supported"));
        proto_tree_add_text(Capabilities_tree, NullTVB, offset, 4, "%s",
                            decode_boolean_bitfield(Capabilities, 0x0010, 32, " NT LM 0.12 SMBs supported", " NT LM 0.12 SMBs not supported"));
        proto_tree_add_text(Capabilities_tree, NullTVB, offset, 4, "%s",
                            decode_boolean_bitfield(Capabilities, 0x0020, 32, " RPC Remote APIs supported", " RPC Remote APIs not supported"));
        proto_tree_add_text(Capabilities_tree, NullTVB, offset, 4, "%s",
                            decode_boolean_bitfield(Capabilities, 0x0040, 32, " NT Status Codes supported", " NT Status Codes not supported"));
        proto_tree_add_text(Capabilities_tree, NullTVB, offset, 4, "%s",
                            decode_boolean_bitfield(Capabilities, 0x0080, 32, " Level 2 OpLocks supported", " Level 2 OpLocks not supported"));
        proto_tree_add_text(Capabilities_tree, NullTVB, offset, 4, "%s",
                            decode_boolean_bitfield(Capabilities, 0x0100, 32, " Lock&Read supported", " Lock&Read not supported"));
        proto_tree_add_text(Capabilities_tree, NullTVB, offset, 4, "%s",
                            decode_boolean_bitfield(Capabilities, 0x0200, 32, " NT Find supported", " NT Find not supported"));
        proto_tree_add_text(Capabilities_tree, NullTVB, offset, 4, "%s",
                            decode_boolean_bitfield(Capabilities, 0x1000, 32, " DFS supported", " DFS not supported"));
        proto_tree_add_text(Capabilities_tree, NullTVB, offset, 4, "%s",
                            decode_boolean_bitfield(Capabilities, 0x4000, 32, " Large READX supported", " Large READX not supported"));
        proto_tree_add_text(Capabilities_tree, NullTVB, offset, 4, "%s",
                            decode_boolean_bitfield(Capabilities, 0x8000, 32, " Large WRITEX supported", " Large WRITEX not supported"));
        proto_tree_add_text(Capabilities_tree, NullTVB, offset, 4, "%s",
                            decode_boolean_bitfield(Capabilities, 0x80000000, 32, " Extended Security Exchanges supported", " Extended Security Exchanges not supported"));

      }

      offset += 4; /* Skip Capabilities */

      /* Build display for: Byte Count */

      ByteCount = GSHORT(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

      }

      offset += 2; /* Skip Byte Count */

      if (ByteCount > 0) {

        /* Build display for: Security Blob */

        SecurityBlob = pd + offset;

        if (SecurityBlobLength > 0) {

          /* XXX - is this ASN.1-encoded?  Is it a Kerberos data structure,
             at least in NT 5.0-and-later server replies? */

          if (tree) {

            proto_tree_add_text(tree, NullTVB, offset, SecurityBlobLength, "Security Blob: %s",
                                bytes_to_str(SecurityBlob, SecurityBlobLength));

          }

          offset += SecurityBlobLength; /* Skip Security Blob */

        }

        /* Build display for: Native OS */

        NativeOS = get_unicode_or_ascii_string(pd, &offset, SMB_offset, si.unicode, &string_len);

        if (tree) {

          proto_tree_add_text(tree, NullTVB, offset, string_len, "Native OS: %s", NativeOS);

        }

        offset += string_len; /* Skip Native OS */

        /* Build display for: Native LanMan Type */

        NativeLanManType = get_unicode_or_ascii_string(pd, &offset, SMB_offset, si.unicode, &string_len);

        if (tree) {

          proto_tree_add_text(tree, NullTVB, offset, string_len, "Native LanMan Type: %s", NativeLanManType);

        }

        offset += string_len; /* Skip Native LanMan Type */

        /* Build display for: Primary Domain */

        PrimaryDomain = get_unicode_or_ascii_string(pd, &offset, SMB_offset, si.unicode, &string_len);

        if (tree) {

          proto_tree_add_text(tree, NullTVB, offset, string_len, "Primary Domain: %s", PrimaryDomain);

        }

        offset += string_len; /* Skip Primary Domain */

      }

      break;

    case 13:

      /* Build display for: AndXCommand */

      AndXCommand = GBYTE(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 1, "AndXCommand: %s", 
			    (AndXCommand == 0xFF ? "No further commands" : decode_smb_name(AndXCommand)));

      }

      offset += 1; /* Skip AndXCommand */

      /* Build display for: AndXReserved */

      AndXReserved = GBYTE(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 1, "AndXReserved: %u", AndXReserved);

      }

      offset += 1; /* Skip AndXReserved */

      /* Build display for: AndXOffset */

      AndXOffset = GSHORT(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 2, "AndXOffset: %u", AndXOffset);

      }

      offset += 2; /* Skip AndXOffset */

      /* Build display for: MaxBufferSize */

      MaxBufferSize = GSHORT(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 2, "MaxBufferSize: %u", MaxBufferSize);

      }

      offset += 2; /* Skip MaxBufferSize */

      /* Build display for: MaxMpxCount */

      MaxMpxCount = GSHORT(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 2, "MaxMpxCount: %u", MaxMpxCount);

      }

      offset += 2; /* Skip MaxMpxCount */

      /* Build display for: VcNumber */

      VcNumber = GSHORT(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 2, "VcNumber: %u", VcNumber);

      }

      offset += 2; /* Skip VcNumber */

      /* Build display for: SessionKey */

      SessionKey = GWORD(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 4, "SessionKey: %u", SessionKey);

      }

      offset += 4; /* Skip SessionKey */

      /* Build display for: ANSI Account Password Length */

      ANSIAccountPasswordLength = GSHORT(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 2, "ANSI Account Password Length: %u", ANSIAccountPasswordLength);

      }

      offset += 2; /* Skip ANSI Account Password Length */

      /* Build display for: UNICODE Account Password Length */

      UNICODEAccountPasswordLength = GSHORT(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 2, "UNICODE Account Password Length: %u", UNICODEAccountPasswordLength);

      }

      offset += 2; /* Skip UNICODE Account Password Length */

      /* Build display for: Reserved */

      Reserved = GWORD(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 4, "Reserved: %u", Reserved);

      }

      offset += 4; /* Skip Reserved */

      /* Build display for: Capabilities */

      Capabilities = GWORD(pd, offset);

      if (tree) {

        ti = proto_tree_add_text(tree, NullTVB, offset, 4, "Capabilities: 0x%08x", Capabilities);
        Capabilities_tree = proto_item_add_subtree(ti, ett_smb_capabilities);
        proto_tree_add_text(Capabilities_tree, NullTVB, offset, 4, "%s",
                            decode_boolean_bitfield(Capabilities, 0x0001, 32, " Raw Mode supported", " Raw Mode not supported"));
        proto_tree_add_text(Capabilities_tree, NullTVB, offset, 4, "%s",
                            decode_boolean_bitfield(Capabilities, 0x0002, 32, " Raw Mode supported", " MPX Mode not supported"));
        proto_tree_add_text(Capabilities_tree, NullTVB, offset, 4, "%s",
                            decode_boolean_bitfield(Capabilities, 0x0004, 32," Unicode supported", " Unicode not supported"));
        proto_tree_add_text(Capabilities_tree, NullTVB, offset, 4, "%s",
                            decode_boolean_bitfield(Capabilities, 0x0008, 32, " Large Files supported", " Large Files not supported"));
        proto_tree_add_text(Capabilities_tree, NullTVB, offset, 4, "%s",
                            decode_boolean_bitfield(Capabilities, 0x0010, 32, " NT LM 0.12 SMBs supported", " NT LM 0.12 SMBs not supported"));
        proto_tree_add_text(Capabilities_tree, NullTVB, offset, 4, "%s",
                            decode_boolean_bitfield(Capabilities, 0x0020, 32, " RPC Remote APIs supported", " RPC Remote APIs not supported"));
        proto_tree_add_text(Capabilities_tree, NullTVB, offset, 4, "%s",
                            decode_boolean_bitfield(Capabilities, 0x0040, 32, " NT Status Codes supported", " NT Status Codes not supported"));
        proto_tree_add_text(Capabilities_tree, NullTVB, offset, 4, "%s",
                            decode_boolean_bitfield(Capabilities, 0x0080, 32, " Level 2 OpLocks supported", " Level 2 OpLocks not supported"));
        proto_tree_add_text(Capabilities_tree, NullTVB, offset, 4, "%s",
                            decode_boolean_bitfield(Capabilities, 0x0100, 32, " Lock&Read supported", " Lock&Read not supported"));
        proto_tree_add_text(Capabilities_tree, NullTVB, offset, 4, "%s",
                            decode_boolean_bitfield(Capabilities, 0x0200, 32, " NT Find supported", " NT Find not supported"));
        proto_tree_add_text(Capabilities_tree, NullTVB, offset, 4, "%s",
                            decode_boolean_bitfield(Capabilities, 0x1000, 32, " DFS supported", " DFS not supported"));
        proto_tree_add_text(Capabilities_tree, NullTVB, offset, 4, "%s",
                            decode_boolean_bitfield(Capabilities, 0x4000, 32, " Large READX supported", " Large READX not supported"));
        proto_tree_add_text(Capabilities_tree, NullTVB, offset, 4, "%s",
                            decode_boolean_bitfield(Capabilities, 0x8000, 32, " Large WRITEX supported", " Large WRITEX not supported"));
        proto_tree_add_text(Capabilities_tree, NullTVB, offset, 4, "%s",
                            decode_boolean_bitfield(Capabilities, 0x80000000, 32, " Extended Security Exchanges supported", " Extended Security Exchanges not supported"));
      
      }

      offset += 4; /* Skip Capabilities */

      /* Build display for: Byte Count */

      ByteCount = GSHORT(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

      }

      offset += 2; /* Skip Byte Count */

      if (ByteCount > 0) {

	/* Build display for: ANSI Password */

	ANSIPassword = pd + offset;

	if (ANSIAccountPasswordLength > 0) {

	    if (tree) {

		proto_tree_add_text(tree, NullTVB, offset, ANSIAccountPasswordLength, "ANSI Password: %s", format_text(ANSIPassword, ANSIAccountPasswordLength));

	    }

	    offset += ANSIAccountPasswordLength; /* Skip ANSI Password */
	}

	/* Build display for: UNICODE Password */

	UNICODEPassword = pd + offset;

	if (UNICODEAccountPasswordLength > 0) {

	  if (tree) {

	    proto_tree_add_text(tree, NullTVB, offset, UNICODEAccountPasswordLength, "UNICODE Password: %s", format_text(UNICODEPassword, UNICODEAccountPasswordLength));

	  }

	  offset += UNICODEAccountPasswordLength; /* Skip UNICODE Password */

	}

	/* Build display for: Account Name */

	AccountName = get_unicode_or_ascii_string(pd, &offset, SMB_offset, si.unicode, &string_len);

	if (tree) {

	  proto_tree_add_text(tree, NullTVB, offset, string_len, "Account Name: %s", AccountName);

	}

	offset += string_len; /* Skip Account Name */

	/* Build display for: Primary Domain */

	/*
	 * XXX - pre-W2K NT systems sometimes appear to stick an extra
	 * byte in front of this, at least if all the strings are
	 * ASCII and the account name is empty.  Another bug?
	 */

	PrimaryDomain = get_unicode_or_ascii_string(pd, &offset, SMB_offset, si.unicode, &string_len);

	if (tree) {

	  proto_tree_add_text(tree, NullTVB, offset, string_len, "Primary Domain: %s", PrimaryDomain);

	}

	offset += string_len; /* Skip Primary Domain */

	/* Build display for: Native OS */

	NativeOS = get_unicode_or_ascii_string(pd, &offset, SMB_offset, si.unicode, &string_len);

	if (tree) {

	  proto_tree_add_text(tree, NullTVB, offset, string_len, "Native OS: %s", NativeOS);

	}

	offset += string_len; /* Skip Native OS */

	/* Build display for: Native LanMan Type */

	/*
	 * XXX - pre-W2K NT systems appear to stick an extra 2 bytes of
	 * padding/null string/whatever in front of this.  W2K doesn't
	 * appear to.  I suspect that's a bug that got fixed; I also
	 * suspect that, in practice, nobody ever looks at that field
	 * because the bug didn't appear to get fixed until NT 5.0....
	 */

	NativeLanManType = get_unicode_or_ascii_string(pd, &offset, SMB_offset, si.unicode, &string_len);

	if (tree) {

	  proto_tree_add_text(tree, NullTVB, offset, string_len, "Native LanMan Type: %s", NativeLanManType);

	}

	offset += string_len; /* Skip Native LanMan Type */

      }

      break;

    default:

      /* XXX - dump the parameter words, one word at a time? */

      offset += WordCount;

      /* Build display for: Byte Count (BCC) */

      ByteCount = GSHORT(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

      }

      offset += 2; /* Skip Byte Count (BCC) */

      break;

    }

    if (AndXCommand != 0xFF) {

      wrap_dissect_smb_command(parent, pd, AndXOffset, tree, AndXCommand,
          &si, max_data, SMB_offset);

    }

  } else {
    /* Response(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    switch (WordCount) {

    case 3:

      /* Build display for: AndXCommand */

      AndXCommand = GBYTE(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 1, "AndXCommand: %s",
                            (AndXCommand == 0xFF ? "No further commands" : decode_smb_name(AndXCommand)));

      }

      offset += 1; /* Skip AndXCommand */

      /* Build display for: AndXReserved */

      AndXReserved = GBYTE(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 1, "AndXReserved: %u", AndXReserved);

      }

      offset += 1; /* Skip AndXReserved */

      /* Build display for: AndXOffset */

      AndXOffset = GSHORT(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 2, "AndXOffset: %u", AndXOffset);

      }

      offset += 2; /* Skip AndXOffset */

      /* Build display for: Action */

      Action = GSHORT(pd, offset);

      if (tree) {

        ti = proto_tree_add_text(tree, NullTVB, offset, 2, "Action: %u", Action);
        Action_tree = proto_item_add_subtree(ti, ett_smb_ssetupandxaction);
        proto_tree_add_text(Action_tree, NullTVB, offset, 2, "%s",
                            decode_boolean_bitfield(Action, 0x0001, 16, "Logged in as GUEST", "Not logged in as GUEST"));

      }

      offset += 2; /* Skip Action */

      /* Build display for: Byte Count (BCC) */

      ByteCount = GSHORT(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

      }

      offset += 2; /* Skip Byte Count (BCC) */

      if (ByteCount > 0) {

        /* Build display for: NativeOS */

        NativeOS = get_unicode_or_ascii_string(pd, &offset, SMB_offset, si.unicode, &string_len);

        if (tree) {

          proto_tree_add_text(tree, NullTVB, offset, string_len, "NativeOS: %s", NativeOS);

        }

        offset += string_len; /* Skip NativeOS */

        /* Build display for: NativeLanMan */

        NativeLanMan = get_unicode_or_ascii_string(pd, &offset, SMB_offset, si.unicode, &string_len);

        if (tree) {

          proto_tree_add_text(tree, NullTVB, offset, string_len, "NativeLanMan: %s", NativeLanMan);

        }

        offset += string_len; /* Skip NativeLanMan */

        /* Build display for: PrimaryDomain */

        PrimaryDomain = get_unicode_or_ascii_string(pd, &offset, SMB_offset, si.unicode, &string_len);

        if (tree) {

          proto_tree_add_text(tree, NullTVB, offset, string_len, "PrimaryDomain: %s", PrimaryDomain);

        }

        offset += string_len; /* Skip PrimaryDomain */

      }

      break;

    case 4:

      /* Build display for: AndXCommand */

      AndXCommand = GBYTE(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 1, "AndXCommand: %s",
			    (AndXCommand == 0xFF ? "No further commands" : decode_smb_name(AndXCommand)));

      }

      offset += 1; /* Skip AndXCommand */

      /* Build display for: AndXReserved */

      AndXReserved = GBYTE(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 1, "AndXReserved: %u", AndXReserved);

      }

      offset += 1; /* Skip AndXReserved */

      /* Build display for: AndXOffset */

      AndXOffset = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "AndXOffset: %u", AndXOffset);

      }


      offset += 2; /* Skip AndXOffset */

      /* Build display for: Action */

      Action = GSHORT(pd, offset);

      if (tree) {

	ti = proto_tree_add_text(tree, NullTVB, offset, 2, "Action: %u", Action);
	Action_tree = proto_item_add_subtree(ti, ett_smb_ssetupandxaction);
	proto_tree_add_text(Action_tree, NullTVB, offset, 2, "%s",
			    decode_boolean_bitfield(Action, 0x0001, 16, "Logged in as GUEST", "Not logged in as GUEST"));

      }

      offset += 2; /* Skip Action */

      /* Build display for: Security Blob Length */

      SecurityBlobLength = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Security Blob Length: %u", SecurityBlobLength);

      }

      offset += 2; /* Skip Security Blob Length */

      /* Build display for: Byte Count (BCC) */

      ByteCount = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

      }

      offset += 2; /* Skip Byte Count (BCC) */

      if (ByteCount > 0) {

	SecurityBlob = pd + offset;

	if (SecurityBlobLength > 0) {

	  /* XXX - is this ASN.1-encoded?  Is it a Kerberos data structure,
	     at least in NT 5.0-and-later server replies? */

	  if (tree) {

	    proto_tree_add_text(tree, NullTVB, offset, SecurityBlobLength, "Security Blob: %s",
				bytes_to_str(SecurityBlob, SecurityBlobLength));

	  }

	  offset += SecurityBlobLength; /* Skip Security Blob */

	}

	/* Build display for: NativeOS */

	NativeOS = get_unicode_or_ascii_string(pd, &offset, SMB_offset, si.unicode, &string_len);

	if (tree) {

	  proto_tree_add_text(tree, NullTVB, offset, string_len, "NativeOS: %s", NativeOS);

	}

	offset += string_len; /* Skip NativeOS */

	/* Build display for: NativeLanMan */

	NativeLanMan = get_unicode_or_ascii_string(pd, &offset, SMB_offset, si.unicode, &string_len);

	if (tree) {

	  proto_tree_add_text(tree, NullTVB, offset, string_len, "NativeLanMan: %s", NativeLanMan);

	}

	offset += string_len; /* Skip NativeLanMan */

      }

      break;

    default:

      /* XXX - dump the parameter words, one word at a time? */

      offset += WordCount;

      /* Build display for: Byte Count (BCC) */

      ByteCount = GSHORT(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

      }

      offset += 2; /* Skip Byte Count (BCC) */

      break;

    }

    if (AndXCommand != 0xFF) {

      wrap_dissect_smb_command(parent, pd, AndXOffset, tree, AndXCommand,
          &si, max_data, SMB_offset);

    }

  }

}

void
dissect_tcon_andx_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset)

{
  guint8      wct, andxcmd = 0xFF;
  guint16     andxoffs = 0, flags, passwdlen, bcc, optionsup;
  const char  *str;
  int         string_len;
  proto_tree  *flags_tree;
  proto_tree  *optionsup_tree;
  proto_item  *ti;

  wct = pd[offset];

  /* Now figure out what format we are talking about, 2, 3, or 4 response
   * words ...
   */

  if (!(si.request && (wct == 4)) && !(!si.request && (wct == 2)) &&
      !(!si.request && (wct == 3)) && !(wct == 0)) {

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Invalid TCON_ANDX format. WCT should be 0, 2, 3, or 4 ..., not %u", wct);

      proto_tree_add_text(tree, NullTVB, offset, END_OF_FRAME, "Data");

      return;

    }
    
  }

  if (tree) {

    proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", wct);

  }

  offset += 1;

  if (wct > 0) {

    andxcmd = pd[offset];

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Next Command: %s",
			  (andxcmd == 0xFF) ? "No further commands":
			  decode_smb_name(andxcmd));
		
      proto_tree_add_text(tree, NullTVB, offset + 1, 1, "Reserved (MBZ): %u", pd[offset+1]);

    }

    offset += 2;

    andxoffs = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Offset to next command: %u", andxoffs);

    }

    offset += 2;

  }

  switch (wct) {

  case 0:

    bcc = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", bcc);

    }

    break;

  case 4:

    flags = GSHORT(pd, offset);

    if (tree) {

      ti = proto_tree_add_text(tree, NullTVB, offset, 2, "Additional Flags: 0x%04x", flags);
      flags_tree = proto_item_add_subtree(ti, ett_smb_aflags);
      proto_tree_add_text(flags_tree, NullTVB, offset, 2, "%s", 
			  decode_boolean_bitfield(flags, 0x0001, 16,
						  "Disconnect TID",
						  "Don't disconnect TID"));

    }

    offset += 2;

    passwdlen = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Password Length: %u", passwdlen);

    }

    offset += 2;

    bcc = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", bcc);

    }

    offset += 2;

    str = pd + offset;

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, strlen(str) + 1, "Password: %s", format_text(str, passwdlen));

    }

    offset += passwdlen;

    str = get_unicode_or_ascii_string(pd, &offset, SMB_offset, si.unicode, &string_len);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, string_len, "Path: %s", str);

    }

    offset += string_len;

    str = pd + offset;

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, strlen(str) + 1, "Service: %s", str);

    }

    break;

  case 2:

    bcc = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", bcc);

    }

    offset += 2;

    str = pd + offset;

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, strlen(str) + 1, "Service Type: %s",
			  str);

    }

    offset += strlen(str) + 1;

    break;

  case 3:

    optionsup = GSHORT(pd, offset);

    if (tree) {

      ti = proto_tree_add_text(tree, NullTVB, offset, 2, "Optional Support: 0x%04x", 
			  optionsup);
      optionsup_tree = proto_item_add_subtree(ti, ett_smb_optionsup);
      proto_tree_add_text(optionsup_tree, NullTVB, offset, 2, "%s",
                          decode_boolean_bitfield(optionsup, 0x0001, 16, "Share supports Search", "Share doesn't support Search"));
      proto_tree_add_text(optionsup_tree, NullTVB, offset, 2, "%s",
                          decode_boolean_bitfield(optionsup, 0x0002, 16, "Share is in DFS", "Share isn't in DFS"));
      
    }

    offset += 2;

    bcc = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", bcc);

    }

    offset += 2;

    /*
     * NOTE: the Service string is always ASCII, even if the "strings are
     * Unicode" bit is set in the flags2 field of the SMB.
     */

    str = pd + offset;

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, strlen(str) + 1, "Service: %s", str);

    }

    offset += strlen(str) + 1;

    str = get_unicode_or_ascii_string(pd, &offset, SMB_offset, si.unicode, &string_len);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, string_len, "Native File System: %s", str);

    }

    offset += string_len;

    
    break;

  default:
	; /* nothing */
	break;
  }

  if (andxcmd != 0xFF) /* Process that next command ... ??? */

    (dissect[andxcmd])(pd, SMB_offset + andxoffs, fd, parent, tree, si, max_data - offset, SMB_offset);

}



void
dissect_open_andx_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset)

{
  static const value_string OpenFunction_0x10[] = {
	{ 0, "Fail if file does not exist"},
	{ 16, "Create file if it does not exist"},
	{ 0, NULL}
  };
  static const value_string OpenFunction_0x03[] = {
	{ 0, "Fail if file exists"},
	{ 1, "Open file if it exists"},
	{ 2, "Truncate File if it exists"},
	{ 0, NULL}
  };
  static const value_string FileType_0xFFFF[] = {
	{ 0, "Disk file or directory"},
	{ 1, "Named pipe in byte mode"},
	{ 2, "Named pipe in message mode"},
	{ 3, "Spooled printer"},
	{ 0, NULL}
  };
  static const value_string DesiredAccess_0x70[] = {
	{ 00, "Compatibility mode"},
	{ 16, "Deny read/write/execute (exclusive)"},
	{ 32, "Deny write"},
	{ 48, "Deny read/execute"},
	{ 64, "Deny none"},
	{ 0, NULL}
  };
  static const value_string DesiredAccess_0x700[] = {
	{ 0, "Locality of reference unknown"},
	{ 256, "Mainly sequential access"},
	{ 512, "Mainly random access"},
	{ 768, "Random access with some locality"},
	{0, NULL}
  };
  static const value_string DesiredAccess_0x4000[] = {
	{ 0, "Write through mode disabled"},
	{ 16384, "Write through mode enabled"},
	{0, NULL}
  };
  static const value_string DesiredAccess_0x1000[] = {
	{ 0, "Normal file (caching permitted)"},
	{ 4096, "Do not cache this file"},
	{0, NULL}
  };
  static const value_string DesiredAccess_0x07[] = {
	{ 0, "Open for reading"},
	{ 1, "Open for writing"},
	{ 2, "Open for reading and writing"},
	{ 3, "Open for execute"},
	{0, NULL}
  };
  static const value_string Action_0x8000[] = {
	{ 0, "File opened by another user (or mode not supported by server)"},
	{ 32768, "File is opened only by this user at present"},
	{0, NULL}
  };
  static const value_string Action_0x0003[] = {
	{ 0, "No action taken?"},
	{ 1, "The file existed and was opened"},
	{ 2, "The file did not exist but was created"},
	{ 3, "The file existed and was truncated"},
	{0, NULL}
  };
  proto_tree    *Search_tree;
  proto_tree    *OpenFunction_tree;
  proto_tree    *Flags_tree;
  proto_tree    *File_tree;
  proto_tree    *FileType_tree;
  proto_tree    *FileAttributes_tree;
  proto_tree    *DesiredAccess_tree;
  proto_tree    *Action_tree;
  proto_item    *ti;
  guint8        WordCount;
  guint8        AndXReserved;
  guint8        AndXCommand = 0xFF;
  guint32       ServerFID;
  guint32       Reserved2;
  guint32       Reserved1;
  guint32       DataSize;
  guint32       AllocatedSize;
  guint16       Search;
  guint16       Reserved;
  guint16       OpenFunction;
  guint16       LastWriteTime;
  guint16       LastWriteDate;
  guint16       GrantedAccess;
  guint16       Flags;
  guint16       FileType;
  guint16       FileAttributes;
  guint16       File;
  guint16       FID;
  guint16       DeviceState;
  guint16       DesiredAccess;
  guint16       CreationTime;
  guint16       CreationDate;
  guint16       ByteCount;
  guint16       AndXOffset = 0;
  guint16       Action;
  const char    *FileName;
  int           string_len;

  if (si.request) {
    /* Request(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    /* Build display for: AndXCommand */

    AndXCommand = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "AndXCommand: %s", 
			  (AndXCommand == 0xFF ? "No further commands" : decode_smb_name(AndXCommand)));

    }

    offset += 1; /* Skip AndXCommand */

    /* Build display for: AndXReserved */

    AndXReserved = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "AndXReserved: %u", AndXReserved);

    }

    offset += 1; /* Skip AndXReserved */

    /* Build display for: AndXOffset */

    AndXOffset = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "AndXOffset: %u", AndXOffset);

    }

    offset += 2; /* Skip AndXOffset */

    /* Build display for: Flags */

    Flags = GSHORT(pd, offset);

    if (tree) {

      ti = proto_tree_add_text(tree, NullTVB, offset, 2, "Flags: 0x%02x", Flags);
      Flags_tree = proto_item_add_subtree(ti, ett_smb_flags);
      proto_tree_add_text(Flags_tree, NullTVB, offset, 2, "%s",
                          decode_boolean_bitfield(Flags, 0x01, 16, "Dont Return Additional Info", "Return Additional Info"));
      proto_tree_add_text(Flags_tree, NullTVB, offset, 2, "%s",
                          decode_boolean_bitfield(Flags, 0x02, 16, "Exclusive OpLock not Requested", "Exclusive OpLock Requested"));
      proto_tree_add_text(Flags_tree, NullTVB, offset, 2, "%s",
                          decode_boolean_bitfield(Flags, 0x04, 16, "Batch OpLock not Requested", "Batch OpLock Requested"));
    
    }

    offset += 2; /* Skip Flags */

    /* Build display for: Desired Access */

    DesiredAccess = GSHORT(pd, offset);

    if (tree) {

      ti = proto_tree_add_text(tree, NullTVB, offset, 2, "Desired Access: 0x%02x", DesiredAccess);
      DesiredAccess_tree = proto_item_add_subtree(ti, ett_smb_desiredaccess);
      proto_tree_add_text(DesiredAccess_tree, NullTVB, offset, 2, "%s",
                          decode_enumerated_bitfield(DesiredAccess, 0x07, 16, DesiredAccess_0x07, "%s"));
      proto_tree_add_text(DesiredAccess_tree, NullTVB, offset, 2, "%s",
                          decode_enumerated_bitfield(DesiredAccess, 0x70, 16, DesiredAccess_0x70, "%s"));
      proto_tree_add_text(DesiredAccess_tree, NullTVB, offset, 2, "%s",
                          decode_enumerated_bitfield(DesiredAccess, 0x700, 16, DesiredAccess_0x700, "%s"));
      proto_tree_add_text(DesiredAccess_tree, NullTVB, offset, 2, "%s",
                          decode_enumerated_bitfield(DesiredAccess, 0x1000, 16, DesiredAccess_0x1000, "%s"));
      proto_tree_add_text(DesiredAccess_tree, NullTVB, offset, 2, "%s",
                          decode_enumerated_bitfield(DesiredAccess, 0x4000, 16, DesiredAccess_0x4000, "%s"));
    
    }

    offset += 2; /* Skip Desired Access */

    /* Build display for: Search */

    Search = GSHORT(pd, offset);

    if (tree) {

      ti = proto_tree_add_text(tree, NullTVB, offset, 2, "Search: 0x%02x", Search);
      Search_tree = proto_item_add_subtree(ti, ett_smb_search);
      proto_tree_add_text(Search_tree, NullTVB, offset, 2, "%s",
                          decode_boolean_bitfield(Search, 0x01, 16, "Read only file", "Not a read only file"));
      proto_tree_add_text(Search_tree, NullTVB, offset, 2, "%s",
                          decode_boolean_bitfield(Search, 0x02, 16, "Hidden file", "Not a hidden file"));
      proto_tree_add_text(Search_tree, NullTVB, offset, 2, "%s",
                          decode_boolean_bitfield(Search, 0x04, 16, "System file", "Not a system file"));
      proto_tree_add_text(Search_tree, NullTVB, offset, 2, "%s",
                          decode_boolean_bitfield(Search, 0x08, 16, " Volume", "Not a volume"));
      proto_tree_add_text(Search_tree, NullTVB, offset, 2, "%s",
                          decode_boolean_bitfield(Search, 0x10, 16, " Directory", "Not a directory"));
      proto_tree_add_text(Search_tree, NullTVB, offset, 2, "%s",
                          decode_boolean_bitfield(Search, 0x20, 16, "Archive file", "Do not archive file"));
    
    }

    offset += 2; /* Skip Search */

    /* Build display for: File */

    File = GSHORT(pd, offset);

    if (tree) {

      ti = proto_tree_add_text(tree, NullTVB, offset, 2, "File: 0x%02x", File);
      File_tree = proto_item_add_subtree(ti, ett_smb_file);
      proto_tree_add_text(File_tree, NullTVB, offset, 2, "%s",
                          decode_boolean_bitfield(File, 0x01, 16, "Read only file", "Not a read only file"));
      proto_tree_add_text(File_tree, NullTVB, offset, 2, "%s",
                          decode_boolean_bitfield(File, 0x02, 16, "Hidden file", "Not a hidden file"));
      proto_tree_add_text(File_tree, NullTVB, offset, 2, "%s",
                          decode_boolean_bitfield(File, 0x04, 16, "System file", "Not a system file"));
      proto_tree_add_text(File_tree, NullTVB, offset, 2, "%s",
                          decode_boolean_bitfield(File, 0x08, 16, " Volume", "Not a volume"));
      proto_tree_add_text(File_tree, NullTVB, offset, 2, "%s",
                          decode_boolean_bitfield(File, 0x10, 16, " Directory", "Not a directory"));
      proto_tree_add_text(File_tree, NullTVB, offset, 2, "%s",
                          decode_boolean_bitfield(File, 0x20, 16, "Archive file", "Do not archive file"));
    
    }

    offset += 2; /* Skip File */

    /* Build display for: Creation Time */

    CreationTime = GSHORT(pd, offset);

    if (tree) {


    }

    offset += 2; /* Skip Creation Time */

    /* Build display for: Creation Date */

    CreationDate = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Creation Date: %s", dissect_smbu_date(CreationDate, CreationTime));
      proto_tree_add_text(tree, NullTVB, offset, 2, "Creation Time: %s", dissect_smbu_time(CreationDate, CreationTime));

    }

    offset += 2; /* Skip Creation Date */

    /* Build display for: Open Function */

    OpenFunction = GSHORT(pd, offset);

    if (tree) {

      ti = proto_tree_add_text(tree, NullTVB, offset, 2, "Open Function: 0x%02x", OpenFunction);
      OpenFunction_tree = proto_item_add_subtree(ti, ett_smb_openfunction);
      proto_tree_add_text(OpenFunction_tree, NullTVB, offset, 2, "%s",
                          decode_enumerated_bitfield(OpenFunction, 0x10, 16, OpenFunction_0x10, "%s"));
      proto_tree_add_text(OpenFunction_tree, NullTVB, offset, 2, "%s",
                          decode_enumerated_bitfield(OpenFunction, 0x03, 16, OpenFunction_0x03, "%s"));
    
    }

    offset += 2; /* Skip Open Function */

    /* Build display for: Allocated Size */

    AllocatedSize = GWORD(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 4, "Allocated Size: %u", AllocatedSize);

    }

    offset += 4; /* Skip Allocated Size */

    /* Build display for: Reserved1 */

    Reserved1 = GWORD(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 4, "Reserved1: %u", Reserved1);

    }

    offset += 4; /* Skip Reserved1 */

    /* Build display for: Reserved2 */

    Reserved2 = GWORD(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 4, "Reserved2: %u", Reserved2);

    }

    offset += 4; /* Skip Reserved2 */

    /* Build display for: Byte Count */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count */

    /* Build display for: File Name */

    FileName = get_unicode_or_ascii_string(pd, &offset, SMB_offset, si.unicode, &string_len);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, string_len, "File Name: %s", FileName);

    }

    offset += string_len; /* Skip File Name */


    if (AndXCommand != 0xFF) {

      wrap_dissect_smb_command(parent, pd, AndXOffset, tree, AndXCommand,
          &si, max_data, SMB_offset);

    }

  } else {
    /* Response(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    if (WordCount != 0) {

      /* Build display for: AndXCommand */

      AndXCommand = GBYTE(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 1, "AndXCommand: %s", 
			    (AndXCommand == 0xFF ? "No further commands" : decode_smb_name(AndXCommand)));

      }

      offset += 1; /* Skip AndXCommand */

      /* Build display for: AndXReserved */

      AndXReserved = GBYTE(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 1, "AndXReserved: %u", AndXReserved);

      }

      offset += 1; /* Skip AndXReserved */

      /* Build display for: AndXOffset */

      AndXOffset = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "AndXOffset: %u", AndXOffset);

      }

      offset += 2; /* Skip AndXOffset */

      /* Build display for: FID */

      FID = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "FID: 0x%04x", FID);

      }

      offset += 2; /* Skip FID */

      /* Build display for: FileAttributes */

      FileAttributes = GSHORT(pd, offset);

      if (tree) {

	ti = proto_tree_add_text(tree, NullTVB, offset, 2, "FileAttributes: 0x%02x", FileAttributes);
	FileAttributes_tree = proto_item_add_subtree(ti, ett_smb_fileattributes);
	proto_tree_add_text(FileAttributes_tree, NullTVB, offset, 2, "%s",
			    decode_boolean_bitfield(FileAttributes, 0x01, 16, "Read only file", "Not a read only file"));
	proto_tree_add_text(FileAttributes_tree, NullTVB, offset, 2, "%s",
			    decode_boolean_bitfield(FileAttributes, 0x02, 16, "Hidden file", "Not a hidden file"));
	proto_tree_add_text(FileAttributes_tree, NullTVB, offset, 2, "%s",
			    decode_boolean_bitfield(FileAttributes, 0x04, 16, "System file", "Not a system file"));
	proto_tree_add_text(FileAttributes_tree, NullTVB, offset, 2, "%s",
			    decode_boolean_bitfield(FileAttributes, 0x08, 16, " Volume", "Not a volume"));
	proto_tree_add_text(FileAttributes_tree, NullTVB, offset, 2, "%s",
			    decode_boolean_bitfield(FileAttributes, 0x10, 16, " Directory", "Not a directory"));
	proto_tree_add_text(FileAttributes_tree, NullTVB, offset, 2, "%s",
			    decode_boolean_bitfield(FileAttributes, 0x20, 16, "Archive file", "Do not archive file"));
    
      }

      offset += 2; /* Skip FileAttributes */

      /* Build display for: Last Write Time */

      LastWriteTime = GSHORT(pd, offset);

      if (tree) {

      }

      offset += 2; /* Skip Last Write Time */

      /* Build display for: Last Write Date */

      LastWriteDate = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Last Write Date: %s", dissect_smbu_date(LastWriteDate, LastWriteTime));
	proto_tree_add_text(tree, NullTVB, offset, 2, "Last Write Time: %s", dissect_smbu_time(LastWriteDate, LastWriteTime));


      }

      offset += 2; /* Skip Last Write Date */

      /* Build display for: Data Size */

      DataSize = GWORD(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 4, "Data Size: %u", DataSize);

      }

      offset += 4; /* Skip Data Size */

      /* Build display for: Granted Access */

      GrantedAccess = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Granted Access: %u", GrantedAccess);

      }

      offset += 2; /* Skip Granted Access */

      /* Build display for: File Type */

      FileType = GSHORT(pd, offset);

      if (tree) {

	ti = proto_tree_add_text(tree, NullTVB, offset, 2, "File Type: 0x%02x", FileType);
	FileType_tree = proto_item_add_subtree(ti, ett_smb_filetype);
	proto_tree_add_text(FileType_tree, NullTVB, offset, 2, "%s",
                          decode_enumerated_bitfield(FileType, 0xFFFF, 16, FileType_0xFFFF, "%s"));
    
      }

      offset += 2; /* Skip File Type */

      /* Build display for: Device State */

      DeviceState = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Device State: %u", DeviceState);

      }

      offset += 2; /* Skip Device State */

      /* Build display for: Action */

      Action = GSHORT(pd, offset);

      if (tree) {

	ti = proto_tree_add_text(tree, NullTVB, offset, 2, "Action: 0x%02x", Action);
	Action_tree = proto_item_add_subtree(ti, ett_smb_openaction);
	proto_tree_add_text(Action_tree, NullTVB, offset, 2, "%s",
			    decode_enumerated_bitfield(Action, 0x8000, 16, Action_0x8000, "%s"));
	proto_tree_add_text(Action_tree, NullTVB, offset, 2, "%s",
			    decode_enumerated_bitfield(Action, 0x0003, 16, Action_0x0003, "%s"));
	
      }
      
      offset += 2; /* Skip Action */

      /* Build display for: Server FID */
      
      ServerFID = GWORD(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 4, "Server FID: 0x%04x", ServerFID);

      }

      offset += 4; /* Skip Server FID */

      /* Build display for: Reserved */

      Reserved = GSHORT(pd, offset);

      if (tree) {
	
	proto_tree_add_text(tree, NullTVB, offset, 2, "Reserved: %u", Reserved);

      }

      offset += 2; /* Skip Reserved */

    }

    /* Build display for: Byte Count */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count */


    if (AndXCommand != 0xFF) {

      wrap_dissect_smb_command(parent, pd, AndXOffset, tree, AndXCommand,
          &si, max_data, SMB_offset);

    }

  }

}

void
dissect_write_raw_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset)

{
  proto_tree    *WriteMode_tree;
  proto_item    *ti;
  guint8        WordCount;
  guint8        Pad;
  guint32       Timeout;
  guint32       Reserved2;
  guint32       Offset;
  guint16       WriteMode;
  guint16       Reserved1;
  guint16       Remaining;
  guint16       FID;
  guint16       DataOffset;
  guint16       DataLength;
  guint16       Count;
  guint16       ByteCount;

  if (si.request) {
    /* Request(s) dissect code */

    WordCount = GBYTE(pd, offset);

    switch (WordCount) {

    case 12:

      /* Build display for: Word Count (WCT) */

      WordCount = GBYTE(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

      }

      offset += 1; /* Skip Word Count (WCT) */

      /* Build display for: FID */

      FID = GSHORT(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 2, "FID: 0x%04x", FID);

      }

      offset += 2; /* Skip FID */

      /* Build display for: Count */

      Count = GSHORT(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 2, "Count: %u", Count);

      }

      offset += 2; /* Skip Count */

      /* Build display for: Reserved 1 */

      Reserved1 = GSHORT(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 2, "Reserved 1: %u", Reserved1);

      }

      offset += 2; /* Skip Reserved 1 */

      /* Build display for: Offset */

      Offset = GWORD(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 4, "Offset: %u", Offset);

      }

      offset += 4; /* Skip Offset */

      /* Build display for: Timeout */

      Timeout = GWORD(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 4, "Timeout: %s", time_msecs_to_str(Timeout));

      }

      offset += 4; /* Skip Timeout */

      /* Build display for: WriteMode */

      WriteMode = GSHORT(pd, offset);

      if (tree) {

        ti = proto_tree_add_text(tree, NullTVB, offset, 2, "WriteMode: 0x%02x", WriteMode);
        WriteMode_tree = proto_item_add_subtree(ti, ett_smb_writemode);
        proto_tree_add_text(WriteMode_tree, NullTVB, offset, 2, "%s",
                            decode_boolean_bitfield(WriteMode, 0x01, 16, "Write through requested", "Write through not requested"));
        proto_tree_add_text(WriteMode_tree, NullTVB, offset, 2, "%s",
                            decode_boolean_bitfield(WriteMode, 0x02, 16, "Return Remaining (pipe/dev)", "Dont return Remaining (pipe/dev)"));
      
      }

      offset += 2; /* Skip WriteMode */

      /* Build display for: Reserved 2 */

      Reserved2 = GWORD(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 4, "Reserved 2: %u", Reserved2);

      }

      offset += 4; /* Skip Reserved 2 */

      /* Build display for: Data Length */

      DataLength = GSHORT(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 2, "Data Length: %u", DataLength);

      }

      offset += 2; /* Skip Data Length */

      /* Build display for: Data Offset */

      DataOffset = GSHORT(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 2, "Data Offset: %u", DataOffset);

      }

      offset += 2; /* Skip Data Offset */

      /* Build display for: Byte Count (BCC) */

      ByteCount = GSHORT(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

      }

      offset += 2; /* Skip Byte Count (BCC) */

      /* Build display for: Pad */

      Pad = GBYTE(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 1, "Pad: %u", Pad);

      }

      offset += 1; /* Skip Pad */

    break;

    case 14:

      /* Build display for: Word Count (WCT) */

      WordCount = GBYTE(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

      }

      offset += 1; /* Skip Word Count (WCT) */

      /* Build display for: FID */

      FID = GSHORT(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 2, "FID: 0x%04x", FID);

      }

      offset += 2; /* Skip FID */

      /* Build display for: Count */

      Count = GSHORT(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 2, "Count: %u", Count);

      }

      offset += 2; /* Skip Count */

      /* Build display for: Reserved 1 */

      Reserved1 = GSHORT(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 2, "Reserved 1: %u", Reserved1);

      }

      offset += 2; /* Skip Reserved 1 */

      /* Build display for: Timeout */

      Timeout = GWORD(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 4, "Timeout: %s", time_msecs_to_str(Timeout));

      }

      offset += 4; /* Skip Timeout */

      /* Build display for: WriteMode */

      WriteMode = GSHORT(pd, offset);

      if (tree) {

        ti = proto_tree_add_text(tree, NullTVB, offset, 2, "WriteMode: 0x%02x", WriteMode);
        WriteMode_tree = proto_item_add_subtree(ti, ett_smb_writemode);
        proto_tree_add_text(WriteMode_tree, NullTVB, offset, 2, "%s",
                            decode_boolean_bitfield(WriteMode, 0x01, 16, "Write through requested", "Write through not requested"));
        proto_tree_add_text(WriteMode_tree, NullTVB, offset, 2, "%s",
                            decode_boolean_bitfield(WriteMode, 0x02, 16, "Return Remaining (pipe/dev)", "Dont return Remaining (pipe/dev)"));
      
      }

      offset += 2; /* Skip WriteMode */

      /* Build display for: Reserved 2 */

      Reserved2 = GWORD(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 4, "Reserved 2: %u", Reserved2);

      }

      offset += 4; /* Skip Reserved 2 */

      /* Build display for: Data Length */

      DataLength = GSHORT(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 2, "Data Length: %u", DataLength);

      }

      offset += 2; /* Skip Data Length */

      /* Build display for: Data Offset */

      DataOffset = GSHORT(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 2, "Data Offset: %u", DataOffset);

      }

      offset += 2; /* Skip Data Offset */

      /* Build display for: Byte Count (BCC) */

      ByteCount = GSHORT(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

      }

      offset += 2; /* Skip Byte Count (BCC) */

      /* Build display for: Pad */

      Pad = GBYTE(pd, offset);

      if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 1, "Pad: %u", Pad);

      }

      offset += 1; /* Skip Pad */

    break;

    }

  } else {
    /* Response(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    if (WordCount != 0) {

      /* Build display for: Remaining */

      Remaining = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Remaining: %u", Remaining);

      }

      offset += 2; /* Skip Remaining */

    }

    /* Build display for: Byte Count */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count */

  }

}


void
dissect_open_print_file_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset)

{
  static const value_string Mode_0x03[] = {
	{ 0, "Text mode (DOS expands TABs)"},
	{ 1, "Graphics mode"},
	{ 0, NULL}
  };
  proto_tree    *Mode_tree;
  proto_item    *ti;
  guint8        WordCount;
  guint8        BufferFormat;
  guint16       SetupLength;
  guint16       Mode;
  guint16       FID;
  guint16       ByteCount;
  const char    *IdentifierString;
  int           string_len;

  if (si.request) {
    /* Request(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    /* Build display for: Setup Length */

    SetupLength = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Setup Length: %u", SetupLength);

    }

    offset += 2; /* Skip Setup Length */

    /* Build display for: Mode */

    Mode = GSHORT(pd, offset);

    if (tree) {

      ti = proto_tree_add_text(tree, NullTVB, offset, 2, "Mode: 0x%02x", Mode);
      Mode_tree = proto_item_add_subtree(ti, ett_smb_mode);
      proto_tree_add_text(Mode_tree, NullTVB, offset, 2, "%s",
                          decode_enumerated_bitfield(Mode, 0x03, 16, Mode_0x03, "%s"));
    
    }

    offset += 2; /* Skip Mode */

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

    /* Build display for: Buffer Format */

    BufferFormat = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Buffer Format: %s (%u)",
			  val_to_str(BufferFormat, buffer_format_vals, "Unknown"),
			  BufferFormat);

    }

    offset += 1; /* Skip Buffer Format */

    /* Build display for: Identifier String */

    IdentifierString = get_unicode_or_ascii_string(pd, &offset, SMB_offset, si.unicode, &string_len);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, string_len, "Identifier String: %s", IdentifierString);

    }

    offset += string_len; /* Skip Identifier String */

  } else {
    /* Response(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    /* Build display for: FID */

    FID = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "FID: 0x%04x", FID);

    }

    offset += 2; /* Skip FID */

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

  }

}


void
dissect_read_andx_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset)

{
  guint8        WordCount;
  guint8        AndXReserved;
  guint8        AndXCommand = 0xFF;
  guint16       ByteCount;
  guint16       AndXOffset = 0;
  guint16       FID;
  guint16       DataCompactionMode;
  guint16       DataLength;
  guint16       DataOffset;
  guint16       Remaining;
  guint16       MaxCount;
  guint16       MinCount;
  guint16       Reserved;
  guint32       Offset;
  guint32       OffsetHigh;
  int           i;

  if (si.request) {
    /* Request(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    /* Build display for: AndXCommand */

    AndXCommand = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "AndXCommand: %u", AndXCommand);

    }

    offset += 1; /* Skip AndXCommand */

    /* Build display for: AndXReserved */

    AndXReserved = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "AndXReserved: %u", AndXReserved);

    }

    offset += 1; /* Skip AndXReserved */

    /* Build display for: AndXOffset */

    AndXOffset = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "AndXOffset: %u", AndXOffset);

    }

    offset += 2; /* Skip AndXOffset */

    /* Build display for: FID */

    FID = GSHORT(pd, offset);

    if (tree) {
	
      proto_tree_add_text(tree, NullTVB, offset, 2, "FID: 0x%04x", FID);
	
    }

    offset += 2; /* Skip FID */

    /* Build display for: Offset */

    Offset = GWORD(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 4, "Offset: %u", Offset);

    }

    offset += 4; /* Skip Offset */

    /* Build display for: Max Count */

    MaxCount = GSHORT(pd, offset);

    if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 2, "Max Count: %u", MaxCount);

    }

    offset += 2; /* Skip Max Count */

    /* Build display for: Min Count */

    MinCount = GSHORT(pd, offset);

    if (tree) {

        proto_tree_add_text(tree, NullTVB, offset, 2, "Min Count: %u", MinCount);

    }

    offset += 2; /* Skip Min Count */

    /* Build display for: Reserved */

    Reserved = GWORD(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 4, "Reserved: %u", Reserved);

    }

    offset += 4; /* Skip Reserved */

    /* Build display for: Remaining */

    Remaining = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Remaining: %u", Remaining);

    }

    offset += 2; /* Skip Remaining */

    if (WordCount == 12) {

	/* Build display for: Offset High */

	OffsetHigh = GWORD(pd, offset);

	if (tree) {

	    proto_tree_add_text(tree, NullTVB, offset, 4, "Offset High: %u", OffsetHigh);

	}

	offset += 4; /* Skip Offset High */
    }

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */


    if (AndXCommand != 0xFF) {

      wrap_dissect_smb_command(parent, pd, AndXOffset, tree, AndXCommand,
          &si, max_data, SMB_offset);

    }

  } else {
    /* Response(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    /* Build display for: AndXCommand */

    AndXCommand = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "AndXCommand: %u", AndXCommand);

    }

    offset += 1; /* Skip AndXCommand */

    /* Build display for: AndXReserved */

    AndXReserved = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "AndXReserved: %u", AndXReserved);

    }

    offset += 1; /* Skip AndXReserved */

    /* Build display for: AndXOffset */

    AndXOffset = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "AndXOffset: %u", AndXOffset);

    }

    offset += 2; /* Skip AndXOffset */

    /* Build display for: Remaining */

    Remaining = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Remaining: %u", Remaining);

    }

    offset += 2; /* Skip Remaining */

    /* Build display for: Data Compaction Mode */

    DataCompactionMode = GSHORT(pd, offset);

    if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Data Compaction Mode: %u", DataCompactionMode);

    }

    offset += 2; /* Skip Data Compaction Mode */

    /* Build display for: Reserved */

    Reserved = GSHORT(pd, offset);

    if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Reserved: %u", Reserved);

    }

    offset += 2; /* Skip Reserved */

    /* Build display for: Data Length */

    DataLength = GSHORT(pd, offset);

    if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Data Length: %u", DataLength);

    }

    offset += 2; /* Skip Data Length */

    /* Build display for: Data Offset */

    DataOffset = GSHORT(pd, offset);

    if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Data Offset: %u", DataOffset);

    }

    offset += 2; /* Skip Data Offset */

    /* Build display for: Reserved[5] */
 
    for(i = 1; i <= 5; ++i) {

	Reserved = GSHORT(pd, offset);

	if (tree) {

	    proto_tree_add_text(tree, NullTVB, offset, 2, "Reserved%u: %u", i, Reserved);

	}
	offset += 2;
    }

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

    /* Build display for data */

    if (tree) {

	offset = SMB_offset + DataOffset;
	if(END_OF_FRAME >= DataLength)
	    proto_tree_add_text(tree, NullTVB, offset, DataLength, "Data (%u bytes)", DataLength);
	else
	    proto_tree_add_text(tree, NullTVB, offset, END_OF_FRAME, "Data (first %u bytes)", END_OF_FRAME);

    }

    if (AndXCommand != 0xFF) {

      wrap_dissect_smb_command(parent, pd, AndXOffset, tree, AndXCommand,
          &si, max_data, SMB_offset);

    }

  }

}

void
dissect_logoff_andx_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset)

{
  guint8        WordCount;
  guint8        AndXReserved;
  guint8        AndXCommand = 0xFF;
  guint16       ByteCount;
  guint16       AndXOffset = 0;

  if (si.request) {
    /* Request(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    if (WordCount != 0) {

      /* Build display for: AndXCommand */

      AndXCommand = GBYTE(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 1, "AndXCommand: %u", AndXCommand);

      }

      offset += 1; /* Skip AndXCommand */

      /* Build display for: AndXReserved */

      AndXReserved = GBYTE(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 1, "AndXReserved: %u", AndXReserved);

      }

      offset += 1; /* Skip AndXReserved */

      /* Build display for: AndXOffset */

      AndXOffset = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "AndXOffset: %u", AndXOffset);

      }

      offset += 2; /* Skip AndXOffset */

    }

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */


    if (AndXCommand != 0xFF) {

      wrap_dissect_smb_command(parent, pd, AndXOffset, tree, AndXCommand,
          &si, max_data, SMB_offset);

    }

  } else {
    /* Response(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    if (WordCount != 0) {

      /* Build display for: AndXCommand */

      AndXCommand = GBYTE(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 1, "AndXCommand: %u", AndXCommand);

      }

      offset += 1; /* Skip AndXCommand */

      /* Build display for: AndXReserved */

      AndXReserved = GBYTE(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 1, "AndXReserved: %u", AndXReserved);

      }

      offset += 1; /* Skip AndXReserved */

      /* Build display for: AndXOffset */

      AndXOffset = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "AndXOffset: %u", AndXOffset);

      }

      offset += 2; /* Skip AndXOffset */

    }

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */


    if (AndXCommand != 0xFF) {

      wrap_dissect_smb_command(parent, pd, AndXOffset, tree, AndXCommand,
          &si, max_data, SMB_offset);

    }

  }

}

void
dissect_seek_file_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset)

{
  static const value_string Mode_0x03[] = {
	{ 0, "Seek from start of file"},
	{ 1, "Seek from current position"},
	{ 2, "Seek from end of file"},
	{ 0, NULL}
  };
  proto_tree    *Mode_tree;
  proto_item    *ti;
  guint8        WordCount;
  guint32       Offset;
  guint16       Mode;
  guint16       FID;
  guint16       ByteCount;

  if (si.request) {
    /* Request(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    /* Build display for: FID */

    FID = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "FID: 0x%04x", FID);

    }

    offset += 2; /* Skip FID */

    /* Build display for: Mode */

    Mode = GSHORT(pd, offset);

    if (tree) {

      ti = proto_tree_add_text(tree, NullTVB, offset, 2, "Mode: 0x%02x", Mode);
      Mode_tree = proto_item_add_subtree(ti, ett_smb_mode);
      proto_tree_add_text(Mode_tree, NullTVB, offset, 2, "%s",
                          decode_enumerated_bitfield(Mode, 0x03, 16, Mode_0x03, "%s"));
    
    }

    offset += 2; /* Skip Mode */

    /* Build display for: Offset */

    Offset = GWORD(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 4, "Offset: %u", Offset);

    }

    offset += 4; /* Skip Offset */

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

  } else {
    /* Response(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    /* Build display for: Offset */

    Offset = GWORD(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 4, "Offset: %u", Offset);

    }

    offset += 4; /* Skip Offset */

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

  }

}

void
dissect_get_print_queue_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset)

{
  guint8        WordCount;
  guint8        BufferFormat;
  guint16       StartIndex;
  guint16       RestartIndex;
  guint16       MaxCount;
  guint16       DataLength;
  guint16       Count;
  guint16       ByteCount;

  if (si.request) {
    /* Request(s) dissect code */

    /* Build display for: Word Count */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count */

    /* Build display for: Max Count */

    MaxCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Max Count: %u", MaxCount);

    }

    offset += 2; /* Skip Max Count */

    /* Build display for: Start Index */

    StartIndex = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Start Index: %u", StartIndex);

    }

    offset += 2; /* Skip Start Index */

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

  } else {
    /* Response(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    if (WordCount != 0) {

      /* Build display for: Count */

      Count = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Count: %u", Count);

      }

      offset += 2; /* Skip Count */

      /* Build display for: Restart Index */

      RestartIndex = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Restart Index: %u", RestartIndex);

      }

      offset += 2; /* Skip Restart Index */

      /* Build display for: Byte Count (BCC) */

    }

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

    /* Build display for: Buffer Format */

    BufferFormat = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Buffer Format: %s (%u)",
			  val_to_str(BufferFormat, buffer_format_vals, "Unknown"),
			  BufferFormat);

    }

    offset += 1; /* Skip Buffer Format */

    /* Build display for: Data Length */

    DataLength = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Data Length: %u", DataLength);

    }

    offset += 2; /* Skip Data Length */

  }

}

void
dissect_locking_andx_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset)

{
  proto_tree    *LockType_tree;
  proto_item    *ti;
  guint8        LockType;
  guint8        WordCount;
  guint8        OplockLevel;
  guint8        AndXReserved;
  guint8        AndXCommand = 0xFF;
  guint32       Timeout;
  guint16       NumberofLocks;
  guint16       NumberOfUnlocks;
  guint16       FID;
  guint16       ByteCount;
  guint16       AndXOffset = 0;

  if (si.request) {
    /* Request(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    /* Build display for: AndXCommand */

    AndXCommand = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "AndXCommand: %s", 
			  (AndXCommand == 0xFF ? "No further commands" : decode_smb_name(AndXCommand)));

    }

    offset += 1; /* Skip AndXCommand */

    /* Build display for: AndXReserved */

    AndXReserved = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "AndXReserved: %u", AndXReserved);

    }

    offset += 1; /* Skip AndXReserved */

    /* Build display for: AndXOffset */

    AndXOffset = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "AndXOffset: %u", AndXOffset);

    }

    offset += 2; /* Skip AndXOffset */

    /* Build display for: FID */

    FID = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "FID: 0x%04x", FID);

    }

    offset += 2; /* Skip FID */

    /* Build display for: Lock Type */

    LockType = GBYTE(pd, offset);

    if (tree) {

      ti = proto_tree_add_text(tree, NullTVB, offset, 1, "Lock Type: 0x%01x", LockType);
      LockType_tree = proto_item_add_subtree(ti, ett_smb_lock_type);
      proto_tree_add_text(LockType_tree, NullTVB, offset, 1, "%s",
                          decode_boolean_bitfield(LockType, 0x01, 16, "Read-only lock", "Not a Read-only lock"));
      proto_tree_add_text(LockType_tree, NullTVB, offset, 1, "%s",
                          decode_boolean_bitfield(LockType, 0x02, 16, "Oplock break notification", "Not an Oplock break notification"));
      proto_tree_add_text(LockType_tree, NullTVB, offset, 1, "%s",
                          decode_boolean_bitfield(LockType, 0x04, 16, "Change lock type", "Not a lock type change"));
      proto_tree_add_text(LockType_tree, NullTVB, offset, 1, "%s",
                          decode_boolean_bitfield(LockType, 0x08, 16, "Cancel outstanding request", "Dont cancel outstanding request"));
      proto_tree_add_text(LockType_tree, NullTVB, offset, 1, "%s",
                          decode_boolean_bitfield(LockType, 0x10, 16, "Large file locking format", "Not a large file locking format"));
    
    }

    offset += 1; /* Skip Lock Type */

    /* Build display for: OplockLevel */

    OplockLevel = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "OplockLevel: %u", OplockLevel);

    }

    offset += 1; /* Skip OplockLevel */

    /* Build display for: Timeout */

    Timeout = GWORD(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 4, "Timeout: %s", time_msecs_to_str(Timeout));

    }

    offset += 4; /* Skip Timeout */

    /* Build display for: Number Of Unlocks */

    NumberOfUnlocks = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Number Of Unlocks: %u", NumberOfUnlocks);

    }

    offset += 2; /* Skip Number Of Unlocks */

    /* Build display for: Number of Locks */

    NumberofLocks = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Number of Locks: %u", NumberofLocks);

    }

    offset += 2; /* Skip Number of Locks */

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */


    if (AndXCommand != 0xFF) {

      wrap_dissect_smb_command(parent, pd, AndXOffset, tree, AndXCommand,
          &si, max_data, SMB_offset);

    }

  } else {
    /* Response(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    if (WordCount != 0) {

      /* Build display for: AndXCommand */

      AndXCommand = GBYTE(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 1, "AndXCommand: %s", 
			    (AndXCommand == 0xFF ? "No further commands" : decode_smb_name(AndXCommand)));

      }

      offset += 1; /* Skip AndXCommand */

      /* Build display for: AndXReserved */

      AndXReserved = GBYTE(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 1, "AndXReserved: %u", AndXReserved);

      }

      offset += 1; /* Skip AndXReserved */

      /* Build display for: AndXOffset */

      AndXOffset = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "AndXOffset: %u", AndXOffset);

      }

      offset += 2; /* Skip AndXOffset */

    }

    /* Build display for: Byte Count */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count */


    if (AndXCommand != 0xFF) {

      wrap_dissect_smb_command(parent, pd, AndXOffset, tree, AndXCommand,
          &si, max_data, SMB_offset);

    }

  }

}

void
dissect_search_dir_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset)

{
  guint8        WordCount;
  guint8        BufferFormat2;
  guint8        BufferFormat1;
  guint8        BufferFormat;
  guint16       SearchAttributes;
  guint16       ResumeKeyLength;
  guint16       MaxCount;
  guint16       DataLength;
  guint16       Count;
  guint16       ByteCount;
  const char    *FileName;
  int           string_len;

  if (si.request) {
    /* Request(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    /* Build display for: Max Count */

    MaxCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Max Count: %u", MaxCount);

    }

    offset += 2; /* Skip Max Count */

    /* Build display for: Search Attributes */

    SearchAttributes = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Search Attributes: %u", SearchAttributes);

    }

    offset += 2; /* Skip Search Attributes */

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

    /* Build display for: Buffer Format 1 */

    BufferFormat1 = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Buffer Format 1: %s (%u)",
			  val_to_str(BufferFormat1, buffer_format_vals, "Unknown"),
			  BufferFormat1);

    }

    offset += 1; /* Skip Buffer Format 1 */

    /* Build display for: File Name */

    FileName = get_unicode_or_ascii_string(pd, &offset, SMB_offset, si.unicode, &string_len);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, string_len, "File Name: %s", FileName);

    }

    offset += string_len; /* Skip File Name */

    /* Build display for: Buffer Format 2 */

    BufferFormat2 = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Buffer Format 2: %s (%u)",
			  val_to_str(BufferFormat2, buffer_format_vals, "Unknown"),
			  BufferFormat2);

    }

    offset += 1; /* Skip Buffer Format 2 */

    /* Build display for: Resume Key Length */

    ResumeKeyLength = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Resume Key Length: %u", ResumeKeyLength);

    }

    offset += 2; /* Skip Resume Key Length */

  } else {
    /* Response(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    if (WordCount != 0) {

      /* Build display for: Count */

      Count = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Count: %u", Count);

      }

      offset += 2; /* Skip Count */

    }

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

    /* Build display for: Buffer Format */

    BufferFormat = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Buffer Format: %s (%u)",
			  val_to_str(BufferFormat, buffer_format_vals, "Unknown"),
			  BufferFormat);

    }

    offset += 1; /* Skip Buffer Format */

    /* Build display for: Data Length */

    DataLength = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Data Length: %u", DataLength);

    }

    offset += 2; /* Skip Data Length */

  }

}


void
dissect_write_print_file_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset)

{
  guint8        WordCount;
  guint8        BufferFormat;
  guint16       FID;
  guint16       DataLength;
  guint16       ByteCount;

  if (si.request) {
    /* Request(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    /* Build display for: FID */

    FID = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "FID: 0x%04x", FID);

    }

    offset += 2; /* Skip FID */

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

    /* Build display for: Buffer Format */

    BufferFormat = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Buffer Format: %s (%u)",
			  val_to_str(BufferFormat, buffer_format_vals, "Unknown"),
			  BufferFormat);

    }

    offset += 1; /* Skip Buffer Format */

    /* Build display for: Data Length */

    DataLength = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Data Length: %u", DataLength);

    }

    offset += 2; /* Skip Data Length */

  } else {
    /* Response(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

  }

}

void
dissect_write_mpx_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset)

{
  proto_tree    *WriteMode_tree;
  proto_item    *ti;
  guint8        WordCount;
  guint8        Pad;
  guint32       Timeout;
  guint32       ResponseMask;
  guint32       RequestMask;
  guint16       WriteMode;
  guint16       Reserved1;
  guint16       FID;
  guint16       DataOffset;
  guint16       DataLength;
  guint16       Count;
  guint16       ByteCount;

  if (si.request) {
    /* Request(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    /* Build display for: FID */

    FID = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "FID: 0x%04x", FID);

    }

    offset += 2; /* Skip FID */

    /* Build display for: Count */

    Count = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Count: %u", Count);

    }

    offset += 2; /* Skip Count */

    /* Build display for: Reserved 1 */

    Reserved1 = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Reserved 1: %u", Reserved1);

    }

    offset += 2; /* Skip Reserved 1 */

    /* Build display for: Timeout */

    Timeout = GWORD(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 4, "Timeout: %s", time_msecs_to_str(Timeout));

    }

    offset += 4; /* Skip Timeout */

    /* Build display for: WriteMode */

    WriteMode = GSHORT(pd, offset);

    if (tree) {

      ti = proto_tree_add_text(tree, NullTVB, offset, 2, "WriteMode: 0x%02x", WriteMode);
      WriteMode_tree = proto_item_add_subtree(ti, ett_smb_writemode);
      proto_tree_add_text(WriteMode_tree, NullTVB, offset, 2, "%s",
                          decode_boolean_bitfield(WriteMode, 0x01, 16, "Write through requested", "Write through not requested"));
      proto_tree_add_text(WriteMode_tree, NullTVB, offset, 2, "%s",
                          decode_boolean_bitfield(WriteMode, 0x02, 16, "Return Remaining", "Dont return Remaining"));
      proto_tree_add_text(WriteMode_tree, NullTVB, offset, 2, "%s",
                          decode_boolean_bitfield(WriteMode, 0x40, 16, "Connectionless mode requested", "Connectionless mode not requested"));
    
    }

    offset += 2; /* Skip WriteMode */

    /* Build display for: Request Mask */

    RequestMask = GWORD(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 4, "Request Mask: %u", RequestMask);

    }

    offset += 4; /* Skip Request Mask */

    /* Build display for: Data Length */

    DataLength = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Data Length: %u", DataLength);

    }

    offset += 2; /* Skip Data Length */

    /* Build display for: Data Offset */

    DataOffset = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Data Offset: %u", DataOffset);

    }

    offset += 2; /* Skip Data Offset */

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

    /* Build display for: Pad */

    Pad = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Pad: %u", Pad);

    }

    offset += 1; /* Skip Pad */

  } else {
    /* Response(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    if (WordCount != 0) {

      /* Build display for: Response Mask */

      ResponseMask = GWORD(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 4, "Response Mask: %u", ResponseMask);

      }

      offset += 4; /* Skip Response Mask */

    }

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

  }

}

void
dissect_find_close2_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset)

{
  guint8        WordCount;
  guint8        ByteCount;
  guint16       FID;

  if (si.request) {
    /* Request(s) dissect code */

    /* Build display for: Word Count (WTC) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WTC): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WTC) */

    /* Build display for: FID */

    FID = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "FID: 0x%04x", FID);

    }

    offset += 2; /* Skip FID */

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

  } else {
    /* Response(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    /* Build display for: Byte Count (BCC) */

    ByteCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 1; /* Skip Byte Count (BCC) */

  }

}

static const value_string trans2_cmd_vals[] = {
  { 0x00, "TRANS2_OPEN" },
  { 0x01, "TRANS2_FIND_FIRST2" },
  { 0x02, "TRANS2_FIND_NEXT2" },
  { 0x03, "TRANS2_QUERY_FS_INFORMATION" },
  { 0x05, "TRANS2_QUERY_PATH_INFORMATION" },
  { 0x06, "TRANS2_SET_PATH_INFORMATION" },
  { 0x07, "TRANS2_QUERY_FILE_INFORMATION" },
  { 0x08, "TRANS2_SET_FILE_INFORMATION" },
  { 0x09, "TRANS2_FSCTL" },
  { 0x0A, "TRANS2_IOCTL2" },
  { 0x0B, "TRANS2_FIND_NOTIFY_FIRST" },
  { 0x0C, "TRANS2_FIND_NOTIFY_NEXT" },
  { 0x0D, "TRANS2_CREATE_DIRECTORY" },
  { 0x0E, "TRANS2_SESSION_SETUP" },
  { 0x10, "TRANS2_GET_DFS_REFERRAL" },
  { 0x11, "TRANS2_REPORT_DFS_INCONSISTENCY" },
  { 0,    NULL }
};

void
dissect_transact2_smb(const u_char *pd, int offset, frame_data *fd, proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data, int SMB_offset)

{
  proto_tree    *Flags_tree;
  proto_item    *ti;
  guint8        WordCount;
  guint8        SetupCount;
  guint8        Reserved3;
  guint8        Reserved1;
  guint8        MaxSetupCount;
  guint8        Data;
  guint32       Timeout;
  guint16       TotalParameterCount;
  guint16       TotalDataCount;
  guint16       Setup;
  guint16       Reserved2;
  guint16       ParameterOffset;
  guint16       ParameterDisplacement;
  guint16       ParameterCount;
  guint16       MaxParameterCount;
  guint16       MaxDataCount;
  guint16       Flags;
  guint16       DataOffset;
  guint16       DataDisplacement;
  guint16       DataCount;
  guint16       ByteCount;
  conversation_t *conversation;
  struct smb_request_val *request_val;
  struct smb_continuation_val *continuation_val;

  /*
   * Find out what conversation this packet is part of.
   * XXX - this should really be done by the transport-layer protocol,
   * although for connectionless transports, we may not want to do that
   * unless we know some higher-level protocol will want it - or we
   * may want to do it, so you can say e.g. "show only the packets in
   * this UDP 'connection'".
   *
   * Note that we don't have to worry about the direction this packet
   * was going - the conversation code handles that for us, treating
   * packets from A:X to B:Y as being part of the same conversation as
   * packets from B:Y to A:X.
   */
  conversation = find_conversation(&pi.src, &pi.dst, pi.ptype,
				pi.srcport, pi.destport, 0);
  if (conversation == NULL) {
    /* It's not part of any conversation - create a new one. */
    conversation = conversation_new(&pi.src, &pi.dst, pi.ptype,
				pi.srcport, pi.destport, 0);
  }

  si.conversation = conversation;  /* Save this for later */

  request_val = do_transaction_hashing(conversation, si, fd);

  si.request_val = request_val;  /* Save this for later */

  if (si.request) {
    /* Request(s) dissect code */
  
    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    /* Build display for: Total Parameter Count */

    TotalParameterCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Total Parameter Count: %u", TotalParameterCount);

    }

    offset += 2; /* Skip Total Parameter Count */

    /* Build display for: Total Data Count */

    TotalDataCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Total Data Count: %u", TotalDataCount);

    }

    offset += 2; /* Skip Total Data Count */

    /* Build display for: Max Parameter Count */

    MaxParameterCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Max Parameter Count: %u", MaxParameterCount);

    }

    offset += 2; /* Skip Max Parameter Count */

    /* Build display for: Max Data Count */

    MaxDataCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Max Data Count: %u", MaxDataCount);

    }

    offset += 2; /* Skip Max Data Count */

    /* Build display for: Max Setup Count */

    MaxSetupCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Max Setup Count: %u", MaxSetupCount);

    }

    offset += 1; /* Skip Max Setup Count */

    /* Build display for: Reserved1 */

    Reserved1 = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Reserved1: %u", Reserved1);

    }

    offset += 1; /* Skip Reserved1 */

    /* Build display for: Flags */

    Flags = GSHORT(pd, offset);

    if (tree) {

      ti = proto_tree_add_text(tree, NullTVB, offset, 2, "Flags: 0x%02x", Flags);
      Flags_tree = proto_item_add_subtree(ti, ett_smb_flags);
      proto_tree_add_text(Flags_tree, NullTVB, offset, 2, "%s",
                          decode_boolean_bitfield(Flags, 0x01, 16, "Also disconnect TID", "Dont disconnect TID"));
      proto_tree_add_text(Flags_tree, NullTVB, offset, 2, "%s",
                          decode_boolean_bitfield(Flags, 0x02, 16, "One way transaction", "Two way transaction"));
    
    }

    offset += 2; /* Skip Flags */

    /* Build display for: Timeout */

    Timeout = GWORD(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 4, "Timeout: %u", Timeout);

    }

    offset += 4; /* Skip Timeout */

    /* Build display for: Reserved2 */

    Reserved2 = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Reserved2: %u", Reserved2);

    }

    offset += 2; /* Skip Reserved2 */

    /* Build display for: Parameter Count */

    if (!BYTES_ARE_IN_FRAME(offset, 2))
      return;

    ParameterCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Parameter Count: %u", ParameterCount);

    }

    offset += 2; /* Skip Parameter Count */

    /* Build display for: Parameter Offset */

    if (!BYTES_ARE_IN_FRAME(offset, 2))
      return;

    ParameterOffset = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Parameter Offset: %u", ParameterOffset);

    }

    offset += 2; /* Skip Parameter Offset */

    /* Build display for: Data Count */

    if (!BYTES_ARE_IN_FRAME(offset, 2))
      return;

    DataCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Data Count: %u", DataCount);

    }

    offset += 2; /* Skip Data Count */

    /* Build display for: Data Offset */

    if (!BYTES_ARE_IN_FRAME(offset, 2))
      return;

    DataOffset = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Data Offset: %u", DataOffset);

    }

    offset += 2; /* Skip Data Offset */

    /* Build display for: Setup Count */

    if (!BYTES_ARE_IN_FRAME(offset, 2))
      return;

    SetupCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Setup Count: %u", SetupCount);

    }

    offset += 1; /* Skip Setup Count */

    /* Build display for: Reserved3 */

    Reserved3 = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Reserved3: %u", Reserved3);

    }

    offset += 1; /* Skip Reserved3 */

    /* Build display for: Setup */

    if (SetupCount != 0) {

      int i;

      if (!BYTES_ARE_IN_FRAME(offset, 2))
	return;

      /*
       * First Setup word is transaction code.
       */
      Setup = GSHORT(pd, offset);

      if (!fd->flags.visited) {
	/*
	 * This is the first time this frame has been seen; remember
	 * the transaction code.
	 */
	g_assert(request_val -> last_transact2_command == -1);
        request_val -> last_transact2_command = Setup;  /* Save for later */
      }

      if (check_col(fd, COL_INFO)) {

	col_add_fstr(fd, COL_INFO, "%s Request",
		     val_to_str(Setup, trans2_cmd_vals, "Unknown (0x%02X)"));

      }

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Setup1: %s",
			  val_to_str(Setup, trans2_cmd_vals, "Unknown (0x%02X)"));

      }

      offset += 2; /* Skip Setup word */

      for (i = 2; i <= SetupCount; i++) {

	if (!BYTES_ARE_IN_FRAME(offset, 2))
	  return;

	Setup = GSHORT(pd, offset);

	if (tree) {

	  proto_tree_add_text(tree, NullTVB, offset, 2, "Setup%i: %u", i, Setup);

	}

	offset += 2; /* Skip Setup word */

      }

    }

    /* Build display for: Byte Count (BCC) */

    if (!BYTES_ARE_IN_FRAME(offset, 2))
      return;

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

    if (offset < (SMB_offset + ParameterOffset)) {

      int pad1Count = SMB_offset + ParameterOffset - offset;

      /* Build display for: Pad1 */

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, pad1Count, "Pad1: %s",
			    bytes_to_str(pd + offset, pad1Count));
      }

      offset += pad1Count; /* Skip Pad1 */

    }

    if (ParameterCount > 0) {

      /* Build display for: Parameters */

      if (tree) {

	proto_tree_add_text(tree, NullTVB, SMB_offset + ParameterOffset,
			    ParameterCount, "Parameters: %s",
			    bytes_to_str(pd + SMB_offset + ParameterOffset,
					 ParameterCount));

      }

      offset += ParameterCount; /* Skip Parameters */

    }

    if (DataCount > 0 && offset < (SMB_offset + DataOffset)) {

      int pad2Count = SMB_offset + DataOffset - offset;
	
      /* Build display for: Pad2 */

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, pad2Count, "Pad2: %s",
			    bytes_to_str(pd + offset, pad2Count));

      }

      offset += pad2Count; /* Skip Pad2 */

    }

    if (DataCount > 0) {

      /* Build display for: Data */

      Data = GBYTE(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, SMB_offset + DataOffset,
			    DataCount, "Data: %s",
			    bytes_to_str(pd + offset, DataCount));

      }

      offset += DataCount; /* Skip Data */

    }
  } else {
    /* Response(s) dissect code */

    /* Pick up the last transact2 command and put it in the right places */

    if (check_col(fd, COL_INFO)) {

      if (request_val == NULL)
	col_set_str(fd, COL_INFO, "Response to unknown SMBtrans2");
      else if (request_val -> last_transact2_command == -1)
	col_set_str(fd, COL_INFO, "Response to SMBtrans2 of unknown type");
      else
	col_add_fstr(fd, COL_INFO, "%s Response",
		     val_to_str(request_val -> last_transact2_command,
				trans2_cmd_vals, "Unknown (0x%02X)"));

    }

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    if (WordCount == 0) {

      /* Interim response. */

      if (check_col(fd, COL_INFO)) {

	if (request_val == NULL)
	  col_set_str(fd, COL_INFO, "Interim response to unknown SMBtrans2");
	else if (request_val -> last_transact2_command == -1)
	  col_set_str(fd, COL_INFO, "Interim response to SMBtrans2 of unknown type");
	else
	  col_add_fstr(fd, COL_INFO, "%s interim response",
		       val_to_str(request_val -> last_transact2_command,
				  trans2_cmd_vals, "Unknown (0x%02X)"));

      }

      /* Build display for: Byte Count (BCC) */

      ByteCount = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

      }

      offset += 2; /* Skip Byte Count (BCC) */

      return;

    }

    /* Build display for: Total Parameter Count */

    TotalParameterCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Total Parameter Count: %u", TotalParameterCount);

    }

    offset += 2; /* Skip Total Parameter Count */

    /* Build display for: Total Data Count */

    TotalDataCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Total Data Count: %u", TotalDataCount);

    }

    offset += 2; /* Skip Total Data Count */

    /* Build display for: Reserved2 */

    Reserved2 = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Reserved2: %u", Reserved2);

    }

    offset += 2; /* Skip Reserved2 */

    /* Build display for: Parameter Count */

    ParameterCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Parameter Count: %u", ParameterCount);

    }

    offset += 2; /* Skip Parameter Count */

    /* Build display for: Parameter Offset */

    ParameterOffset = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Parameter Offset: %u", ParameterOffset);

    }

    offset += 2; /* Skip Parameter Offset */

    /* Build display for: Parameter Displacement */

    ParameterDisplacement = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Parameter Displacement: %u", ParameterDisplacement);

    }

    offset += 2; /* Skip Parameter Displacement */

    /* Build display for: Data Count */

    DataCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Data Count: %u", DataCount);

    }

    offset += 2; /* Skip Data Count */

    /* Build display for: Data Offset */

    DataOffset = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Data Offset: %u", DataOffset);

    }

    offset += 2; /* Skip Data Offset */

    /* Build display for: Data Displacement */

    if (!BYTES_ARE_IN_FRAME(offset, 2))
      return;

    DataDisplacement = GSHORT(pd, offset);
    si.ddisp = DataDisplacement;

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Data Displacement: %u", DataDisplacement);

    }

    offset += 2; /* Skip Data Displacement */

    /* Build display for: Setup Count */

    SetupCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Setup Count: %u", SetupCount);

    }

    offset += 1; /* Skip Setup Count */

    /* Build display for: Reserved3 */

    Reserved3 = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Reserved3: %u", Reserved3);

    }

    offset += 1; /* Skip Reserved3 */

    if (SetupCount != 0) {

      int i;

      for (i = 1; i <= SetupCount; i++) {
	
	Setup = GSHORT(pd, offset);

	if (tree) {

	  proto_tree_add_text(tree, NullTVB, offset, 2, "Setup%i: %u", i, Setup);

	}

	offset += 2; /* Skip Setup */

      }
    }

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

    if (offset < (SMB_offset + ParameterOffset)) {

      int pad1Count = SMB_offset + ParameterOffset - offset;

      /* Build display for: Pad1 */

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, pad1Count, "Pad1: %s",
			    bytes_to_str(pd + offset, pad1Count));
      }

      offset += pad1Count; /* Skip Pad1 */

    }

    /* Build display for: Parameters */

    if (ParameterCount > 0) {

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, ParameterCount,
			    "Parameters: %s",
			    bytes_to_str(pd + offset, ParameterCount));

      }

      offset += ParameterCount; /* Skip Parameters */

    }

    if (DataCount > 0 && offset < (SMB_offset + DataOffset)) {

      int pad2Count = SMB_offset + DataOffset - offset;
	
      /* Build display for: Pad2 */

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, pad2Count, "Pad2: %s",
			    bytes_to_str(pd + offset, pad2Count));

      }

      offset += pad2Count; /* Skip Pad2 */

    }

    /* Build display for: Data */

    if (DataCount > 0) {

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, DataCount,
			    "Data: %s",
			    bytes_to_str(pd + offset, DataCount));

      }

      offset += DataCount; /* Skip Data */

    }

  }

}


static void 
dissect_transact_params(const u_char *pd, int offset, frame_data *fd,
    proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data,
    int SMB_offset, int DataOffset, int DataCount,
    int ParameterOffset, int ParameterCount, int SetupAreaOffset,
    int SetupCount, const char *TransactName)
{
  char             *TransactNameCopy;
  char             *trans_type = NULL, *trans_cmd, *loc_of_slash = NULL;
  int              index;
  const gchar      *Data;
  packet_info      *pinfo;
  tvbuff_t         *next_tvb;
  tvbuff_t         *setup_tvb;

  if (TransactName != NULL) {
    /* Should check for error here ... */

    TransactNameCopy = g_strdup(TransactName);

    if (TransactNameCopy[0] == '\\') {
      trans_type = TransactNameCopy + 1;  /* Skip the slash */
      loc_of_slash = trans_type ? strchr(trans_type, '\\') : NULL;
    }

    if (loc_of_slash) {
      index = loc_of_slash - trans_type;  /* Make it a real index */
      trans_cmd = trans_type + index + 1;
      trans_type[index] = '\0';
    }
    else
      trans_cmd = NULL;
  } else
    trans_cmd = NULL;

  pinfo = &pi;

  /*
   * Number of bytes of parameter.
   */
  si.parameter_count = ParameterCount;

  if (DataOffset < 0) {
    /*
     * This is an interim response, so there're no parameters or data
     * to dissect.
     */
    si.is_interim_response = TRUE;

    /*
     * Create a zero-length tvbuff.
     */
    next_tvb = tvb_create_from_top(pi.captured_len);
  } else {
    /*
     * This isn't an interim response.
     */
    si.is_interim_response = FALSE;

    /*
     * Create a tvbuff for the parameters and data.
     */
    next_tvb = tvb_create_from_top(SMB_offset + ParameterOffset);
  }

  /*
   * Offset of beginning of data from beginning of next_tvb.
   */
  si.data_offset = DataOffset - ParameterOffset;

  /*
   * Number of bytes of data.
   */
  si.data_count = DataCount;

  /*
   * Command.
   */
  si.trans_cmd = trans_cmd;

  /*
   * Pass "si" to the subdissector.
   */
  pinfo->private_data = &si;

  /*
   * Tvbuff for setup area, for mailslot call.
   */
  /*
   * Is there a setup area?
   */
  if (SetupAreaOffset < 0) {
    /*
     * No - create a zero-length tvbuff.
     */
    setup_tvb = tvb_create_from_top(pi.captured_len);
  } else {
    /*
     * Create a tvbuff for the setup area.
     */
    setup_tvb = tvb_create_from_top(SetupAreaOffset);
  }

  if ((trans_cmd == NULL) ||
      (((trans_type == NULL || strcmp(trans_type, "MAILSLOT") != 0) ||
       !dissect_mailslot_smb(setup_tvb, next_tvb, pinfo, parent)) &&
      ((trans_type == NULL || strcmp(trans_type, "PIPE") != 0) ||
       !dissect_pipe_smb(next_tvb, pinfo, parent)))) {

    if (ParameterCount > 0) {

      /* Build display for: Parameters */
      
      if (tree) {

	proto_tree_add_text(tree, NullTVB, SMB_offset + ParameterOffset,
			    ParameterCount, "Parameters: %s",
			    bytes_to_str(pd + SMB_offset + ParameterOffset,
					 ParameterCount));
	  
      }
	
      offset = SMB_offset + ParameterOffset + ParameterCount; /* Skip Parameters */

    }

    if (DataCount > 0 && offset < (SMB_offset + DataOffset)) {

      int pad2Count = SMB_offset + DataOffset - offset;
	
      /* Build display for: Pad2 */

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, pad2Count, "Pad2: %s",
			    bytes_to_str(pd + offset, pad2Count));

      }

      offset += pad2Count; /* Skip Pad2 */

    }

    if (DataCount > 0) {

      /* Build display for: Data */

      Data = pd + SMB_offset + DataOffset;

      if (tree) {

	proto_tree_add_text(tree, NullTVB, SMB_offset + DataOffset, DataCount,
			    "Data: %s",
			    bytes_to_str(pd + SMB_offset + DataOffset, DataCount));

      }

      offset += DataCount; /* Skip Data */

    }
  }

}

void
dissect_transact_smb(const u_char *pd, int offset, frame_data *fd,
		     proto_tree *parent, proto_tree *tree,
		     struct smb_info si, int max_data, int SMB_offset)
{
  proto_tree    *Flags_tree;
  proto_item    *ti;
  guint8        WordCount;
  guint8        SetupCount;
  guint8        Reserved3;
  guint8        Reserved1;
  guint8        MaxSetupCount;
  guint32       Timeout;
  guint16       TotalParameterCount;
  guint16       TotalDataCount;
  guint16       Setup = 0;
  guint16       Reserved2;
  guint16       ParameterOffset;
  guint16       ParameterDisplacement;
  guint16       ParameterCount;
  guint16       MaxParameterCount;
  guint16       MaxDataCount;
  guint16       Flags;
  guint16       DataOffset;
  guint16       DataDisplacement;
  guint16       DataCount;
  guint16       ByteCount;
  int           TNlen;
  const char    *TransactName;
  conversation_t *conversation;
  struct smb_request_val *request_val;
  guint16	SetupAreaOffset;

  /*
   * Find out what conversation this packet is part of
   */

  conversation = find_conversation(&pi.src, &pi.dst, pi.ptype,
				   pi.srcport, pi.destport, 0);

  if (conversation == NULL) {  /* Create a new conversation */

    conversation = conversation_new(&pi.src, &pi.dst, pi.ptype,
				    pi.srcport, pi.destport, 0);

  }

  si.conversation = conversation;  /* Save this */

  request_val = do_transaction_hashing(conversation, si, fd);

  si.request_val = request_val;  /* Save this for later */

  if (si.request) {
    /* Request(s) dissect code */

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    /* Build display for: Total Parameter Count */

    TotalParameterCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Total Parameter Count: %u", TotalParameterCount);

    }

    offset += 2; /* Skip Total Parameter Count */

    /* Build display for: Total Data Count */

    if (!BYTES_ARE_IN_FRAME(offset, 2))
      return;

    TotalDataCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Total Data Count: %u", TotalDataCount);

    }

    offset += 2; /* Skip Total Data Count */

    /* Build display for: Max Parameter Count */

    MaxParameterCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Max Parameter Count: %u", MaxParameterCount);

    }

    offset += 2; /* Skip Max Parameter Count */

    /* Build display for: Max Data Count */

    MaxDataCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Max Data Count: %u", MaxDataCount);

    }

    offset += 2; /* Skip Max Data Count */

    /* Build display for: Max Setup Count */

    MaxSetupCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Max Setup Count: %u", MaxSetupCount);

    }

    offset += 1; /* Skip Max Setup Count */

    /* Build display for: Reserved1 */

    Reserved1 = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Reserved1: %u", Reserved1);

    }

    offset += 1; /* Skip Reserved1 */

    /* Build display for: Flags */

    Flags = GSHORT(pd, offset);

    if (tree) {

      ti = proto_tree_add_text(tree, NullTVB, offset, 2, "Flags: 0x%02x", Flags);
      Flags_tree = proto_item_add_subtree(ti, ett_smb_flags);
      proto_tree_add_text(Flags_tree, NullTVB, offset, 2, "%s",
                          decode_boolean_bitfield(Flags, 0x01, 16, "Also disconnect TID", "Dont disconnect TID"));
      proto_tree_add_text(Flags_tree, NullTVB, offset, 2, "%s",
                          decode_boolean_bitfield(Flags, 0x02, 16, "One way transaction", "Two way transaction"));
    
    }

    offset += 2; /* Skip Flags */

    /* Build display for: Timeout */

    Timeout = GWORD(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 4, "Timeout: %u", Timeout);

    }

    offset += 4; /* Skip Timeout */

    /* Build display for: Reserved2 */

    Reserved2 = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Reserved2: %u", Reserved2);

    }

    offset += 2; /* Skip Reserved2 */

    /* Build display for: Parameter Count */

    if (!BYTES_ARE_IN_FRAME(offset, 2))
      return;

    ParameterCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Parameter Count: %u", ParameterCount);

    }

    offset += 2; /* Skip Parameter Count */

    /* Build display for: Parameter Offset */

    if (!BYTES_ARE_IN_FRAME(offset, 2))
      return;

    ParameterOffset = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Parameter Offset: %u", ParameterOffset);

    }

    offset += 2; /* Skip Parameter Offset */

    /* Build display for: Data Count */

    if (!BYTES_ARE_IN_FRAME(offset, 2))
      return;

    DataCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Data Count: %u", DataCount);

    }

    offset += 2; /* Skip Data Count */

    /* Build display for: Data Offset */

    if (!BYTES_ARE_IN_FRAME(offset, 2))
      return;

    DataOffset = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Data Offset: %u", DataOffset);

    }

    offset += 2; /* Skip Data Offset */

    /* Build display for: Setup Count */

    if (!BYTES_ARE_IN_FRAME(offset, 2))
      return;

    SetupCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Setup Count: %u", SetupCount);

    }

    offset += 1; /* Skip Setup Count */

    /* Build display for: Reserved3 */

    Reserved3 = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Reserved3: %u", Reserved3);
    }

    offset += 1; /* Skip Reserved3 */
 
    SetupAreaOffset = offset;

    /* Build display for: Setup */

    if (SetupCount > 0) {

      int i = SetupCount;

      if (!BYTES_ARE_IN_FRAME(offset, 2))
	return;

      Setup = GSHORT(pd, offset);

      for (i = 1; i <= SetupCount; i++) {
	
	if (!BYTES_ARE_IN_FRAME(offset, 2))
	  return;

	Setup = GSHORT(pd, offset);

	if (tree) {

	  proto_tree_add_text(tree, NullTVB, offset, 2, "Setup%i: %u", i, Setup);

	}

	offset += 2; /* Skip Setup */

      }

    }

    /* Build display for: Byte Count (BCC) */

    if (!BYTES_ARE_IN_FRAME(offset, 2))
      return;

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

    /* Build display for: Transact Name */

    TransactName = get_unicode_or_ascii_string(pd, &offset, SMB_offset, si.unicode, &TNlen);

    if (!fd->flags.visited) {
      /*
       * This is the first time this frame has been seen; remember
       * the transaction name.
       */
      g_assert(request_val -> last_transact_command == NULL);
      request_val -> last_transact_command = g_strdup(TransactName);
    }

    if (check_col(fd, COL_INFO)) {

      col_add_fstr(fd, COL_INFO, "%s Request", TransactName);

    }

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, TNlen, "Transact Name: %s", TransactName);

    }

    offset += TNlen; /* Skip Transact Name */
    if (si.unicode) offset += 2;   /* There are two more extraneous bytes there*/

    if (offset < (SMB_offset + ParameterOffset)) {

      int pad1Count = SMB_offset + ParameterOffset - offset;

      /* Build display for: Pad1 */

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, pad1Count, "Pad1: %s",
			    bytes_to_str(pd + offset, pad1Count));
      }

      offset += pad1Count; /* Skip Pad1 */

    }

    /* Let's see if we can decode this */

    dissect_transact_params(pd, offset, fd, parent, tree, si, max_data,
			    SMB_offset, DataOffset, DataCount,
			    ParameterOffset, ParameterCount,
			    SetupAreaOffset, SetupCount, TransactName);

  } else {
    /* Response(s) dissect code */

    if (check_col(fd, COL_INFO)) {
      if ( request_val == NULL )
	col_set_str(fd, COL_INFO, "Response to unknown SMBtrans");
      else if (request_val -> last_transact_command == NULL)
	col_set_str(fd, COL_INFO, "Response to SMBtrans of unknown type");
      else
	col_add_fstr(fd, COL_INFO, "%s Response",
		     request_val -> last_transact_command);

    }

    /* Build display for: Word Count (WCT) */

    WordCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Word Count (WCT): %u", WordCount);

    }

    offset += 1; /* Skip Word Count (WCT) */

    if (WordCount == 0) {

      /* Interim response. */

      if (check_col(fd, COL_INFO)) {
	if ( request_val == NULL )
	  col_set_str(fd, COL_INFO, "Interim response to unknown SMBtrans");
	else if (request_val -> last_transact_command == NULL)
	  col_set_str(fd, COL_INFO, "Interim response to SMBtrans of unknown type");
	else
	  col_add_fstr(fd, COL_INFO, "%s interim response",
		       request_val -> last_transact_command);

      }

      /* Build display for: Byte Count (BCC) */

      ByteCount = GSHORT(pd, offset);

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

      }

      offset += 2; /* Skip Byte Count (BCC) */

      /* Dissect the interim response by showing the type of request to
         which it's a reply, if we have that information. */
      if (request_val != NULL) {
	dissect_transact_params(pd, offset, fd, parent, tree, si, max_data,
				SMB_offset, -1, -1, -1, -1, -1, -1,
	  			request_val -> last_transact_command);
      }

      return;

    }

    /* Build display for: Total Parameter Count */

    TotalParameterCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Total Parameter Count: %u", TotalParameterCount);

    }

    offset += 2; /* Skip Total Parameter Count */

    /* Build display for: Total Data Count */

    TotalDataCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Total Data Count: %u", TotalDataCount);

    }

    offset += 2; /* Skip Total Data Count */

    /* Build display for: Reserved2 */

    Reserved2 = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Reserved2: %u", Reserved2);

    }

    offset += 2; /* Skip Reserved2 */

    /* Build display for: Parameter Count */

    ParameterCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Parameter Count: %u", ParameterCount);

    }

    offset += 2; /* Skip Parameter Count */

    /* Build display for: Parameter Offset */

    ParameterOffset = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Parameter Offset: %u", ParameterOffset);

    }

    offset += 2; /* Skip Parameter Offset */

    /* Build display for: Parameter Displacement */

    ParameterDisplacement = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Parameter Displacement: %u", ParameterDisplacement);

    }

    offset += 2; /* Skip Parameter Displacement */

    /* Build display for: Data Count */

    DataCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Data Count: %u", DataCount);

    }

    offset += 2; /* Skip Data Count */

    /* Build display for: Data Offset */

    DataOffset = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Data Offset: %u", DataOffset);

    }

    offset += 2; /* Skip Data Offset */

    /* Build display for: Data Displacement */

    if (!BYTES_ARE_IN_FRAME(offset, 2))
      return;

    DataDisplacement = GSHORT(pd, offset);
    si.ddisp = DataDisplacement;

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Data Displacement: %u", DataDisplacement);

    }

    offset += 2; /* Skip Data Displacement */

    /* Build display for: Setup Count */

    SetupCount = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Setup Count: %u", SetupCount);

    }

    offset += 1; /* Skip Setup Count */

 
    /* Build display for: Reserved3 */

    Reserved3 = GBYTE(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 1, "Reserved3: %u", Reserved3);

    }


    offset += 1; /* Skip Reserved3 */
 
    SetupAreaOffset = offset;	

    /* Build display for: Setup */

    if (SetupCount > 0) {

      int i = SetupCount;

      Setup = GSHORT(pd, offset);

      for (i = 1; i <= SetupCount; i++) {
	
	Setup = GSHORT(pd, offset);

	if (tree) {

	  proto_tree_add_text(tree, NullTVB, offset, 2, "Setup%i: %u", i, Setup);

	}

	offset += 2; /* Skip Setup */

      }

    }

    /* Build display for: Byte Count (BCC) */

    ByteCount = GSHORT(pd, offset);

    if (tree) {

      proto_tree_add_text(tree, NullTVB, offset, 2, "Byte Count (BCC): %u", ByteCount);

    }

    offset += 2; /* Skip Byte Count (BCC) */

    /* Build display for: Pad1 */

    if (offset < (SMB_offset + ParameterOffset)) {

      int pad1Count = SMB_offset + ParameterOffset - offset;

      /* Build display for: Pad1 */

      if (tree) {

	proto_tree_add_text(tree, NullTVB, offset, pad1Count, "Pad1: %s",
			    bytes_to_str(pd + offset, pad1Count));
      }

      offset += pad1Count; /* Skip Pad1 */

    }

    if (request_val != NULL)
      TransactName = request_val -> last_transact_command;
    else
      TransactName = NULL;

    /*
     * Make an entry for this, if it's continued; get the entry for
     * the message of which it's a continuation, and get the transaction
     * name for that message, if it's a continuation.
     *
     * XXX - eventually, do reassembly of all the continuations, so
     * we can dissect the entire reply.
     */
    si.continuation_val = do_continuation_hashing(conversation, si, fd,
					          TotalDataCount, DataCount,
					          &TransactName);
    dissect_transact_params(pd, offset, fd, parent, tree, si, max_data,
			    SMB_offset, DataOffset, DataCount,
			    ParameterOffset, ParameterCount,
			    SetupAreaOffset, SetupCount, TransactName);

  }

}





static void (*dissect[256])(const u_char *, int, frame_data *, proto_tree *, proto_tree *, struct smb_info, int, int) = {

  dissect_unknown_smb,
  dissect_unknown_smb,
  dissect_unknown_smb,
  dissect_unknown_smb,
  dissect_unknown_smb,
  dissect_unknown_smb,
  dissect_unknown_smb,
  dissect_unknown_smb,
  dissect_unknown_smb,
  dissect_unknown_smb,
  dissect_unknown_smb,
  dissect_unknown_smb,
  dissect_unknown_smb,
  dissect_unknown_smb,
  dissect_unknown_smb,
  dissect_unknown_smb,
  dissect_unknown_smb,
  dissect_unknown_smb,
  dissect_unknown_smb,
  dissect_unknown_smb,
  dissect_unknown_smb,
  dissect_unknown_smb,
  dissect_unknown_smb,
  dissect_unknown_smb,
  dissect_unknown_smb,
  dissect_unknown_smb,      /* unknown SMB 0x19 */
  dissect_unknown_smb,
  dissect_read_mpx_smb,     /* SMBreadBmpx read block multiplexed */
  dissect_unknown_smb,      /* SMBreadBs read block (secondary response) */
  dissect_write_raw_smb,    /* SMBwriteBraw write block raw */
  dissect_write_mpx_smb,    /* SMBwriteBmpx write block multiplexed */
  dissect_unknown_smb,      /* SMBwriteBs write block (secondary request) */
  dissect_unknown_smb,
  dissect_unknown_smb,      /* unknown SMB 0x21 */
  dissect_unknown_smb,
  dissect_unknown_smb,
  dissect_locking_andx_smb, /* SMBlockingX lock/unlock byte ranges and X */
  dissect_transact_smb,      /* SMBtrans transaction - name, bytes in/out */
  dissect_unknown_smb,
  dissect_unknown_smb,
  dissect_unknown_smb,
  dissect_unknown_smb,
  dissect_unknown_smb,
  dissect_unknown_smb,
  dissect_unknown_smb,
  dissect_open_andx_smb,      /* SMBopenX open and X */
  dissect_read_andx_smb,    /* SMBreadX read and X */
  dissect_unknown_smb,      /* SMBwriteX write and X */
  dissect_unknown_smb,      /* unknown SMB 0x30 */
  dissect_unknown_smb,      /* unknown SMB 0x31 */
  dissect_transact2_smb,    /* unknown SMB 0x32 */
  dissect_unknown_smb,      /* unknown SMB 0x33 */
  dissect_find_close2_smb,  /* unknown SMB 0x34 */
  dissect_unknown_smb,      /* unknown SMB 0x35 */
  dissect_unknown_smb,      /* unknown SMB 0x36 */
  dissect_unknown_smb,      /* unknown SMB 0x37 */
  dissect_unknown_smb,      /* unknown SMB 0x38 */
  dissect_unknown_smb,      /* unknown SMB 0x39 */
  dissect_unknown_smb,      /* unknown SMB 0x3a */
  dissect_unknown_smb,      /* unknown SMB 0x3b */
  dissect_unknown_smb,      /* unknown SMB 0x3c */
  dissect_unknown_smb,      /* unknown SMB 0x3d */
  dissect_unknown_smb,      /* unknown SMB 0x3e */
  dissect_unknown_smb,      /* unknown SMB 0x3f */
  dissect_unknown_smb,      /* unknown SMB 0x40 */
  dissect_unknown_smb,      /* unknown SMB 0x41 */
  dissect_unknown_smb,      /* unknown SMB 0x42 */
  dissect_unknown_smb,      /* unknown SMB 0x43 */
  dissect_unknown_smb,      /* unknown SMB 0x44 */
  dissect_unknown_smb,      /* unknown SMB 0x45 */
  dissect_unknown_smb,      /* unknown SMB 0x46 */
  dissect_unknown_smb,      /* unknown SMB 0x47 */
  dissect_unknown_smb,      /* unknown SMB 0x48 */
  dissect_unknown_smb,      /* unknown SMB 0x49 */
  dissect_unknown_smb,      /* unknown SMB 0x4a */
  dissect_unknown_smb,      /* unknown SMB 0x4b */
  dissect_unknown_smb,      /* unknown SMB 0x4c */
  dissect_unknown_smb,      /* unknown SMB 0x4d */
  dissect_unknown_smb,      /* unknown SMB 0x4e */
  dissect_unknown_smb,      /* unknown SMB 0x4f */
  dissect_unknown_smb,      /* unknown SMB 0x50 */
  dissect_unknown_smb,      /* unknown SMB 0x51 */
  dissect_unknown_smb,      /* unknown SMB 0x52 */
  dissect_unknown_smb,      /* unknown SMB 0x53 */
  dissect_unknown_smb,      /* unknown SMB 0x54 */
  dissect_unknown_smb,      /* unknown SMB 0x55 */
  dissect_unknown_smb,      /* unknown SMB 0x56 */
  dissect_unknown_smb,      /* unknown SMB 0x57 */
  dissect_unknown_smb,      /* unknown SMB 0x58 */
  dissect_unknown_smb,      /* unknown SMB 0x59 */
  dissect_unknown_smb,      /* unknown SMB 0x5a */
  dissect_unknown_smb,      /* unknown SMB 0x5b */
  dissect_unknown_smb,      /* unknown SMB 0x5c */
  dissect_unknown_smb,      /* unknown SMB 0x5d */
  dissect_unknown_smb,      /* unknown SMB 0x5e */
  dissect_unknown_smb,      /* unknown SMB 0x5f */
  dissect_unknown_smb,      /* unknown SMB 0x60 */
  dissect_unknown_smb,      /* unknown SMB 0x61 */
  dissect_unknown_smb,      /* unknown SMB 0x62 */
  dissect_unknown_smb,      /* unknown SMB 0x63 */
  dissect_unknown_smb,      /* unknown SMB 0x64 */
  dissect_unknown_smb,      /* unknown SMB 0x65 */
  dissect_unknown_smb,      /* unknown SMB 0x66 */
  dissect_unknown_smb,      /* unknown SMB 0x67 */
  dissect_unknown_smb,      /* unknown SMB 0x68 */
  dissect_unknown_smb,      /* unknown SMB 0x69 */
  dissect_unknown_smb,      /* unknown SMB 0x6a */
  dissect_unknown_smb,      /* unknown SMB 0x6b */
  dissect_unknown_smb,      /* unknown SMB 0x6c */
  dissect_unknown_smb,      /* unknown SMB 0x6d */
  dissect_unknown_smb,      /* unknown SMB 0x6e */
  dissect_unknown_smb,      /* unknown SMB 0x6f */
  dissect_unknown_smb,
  dissect_unknown_smb,
  dissect_unknown_smb,
  dissect_ssetup_andx_smb,  /* SMBsesssetupX Session Set Up & X (including User Logon) */
  dissect_logoff_andx_smb,  /* SMBlogof Logoff & X */
  dissect_tcon_andx_smb,    /* SMBtconX tree connect and X */
  dissect_unknown_smb,      /* unknown SMB 0x76 */
  dissect_unknown_smb,      /* unknown SMB 0x77 */
  dissect_unknown_smb,      /* unknown SMB 0x78 */
  dissect_unknown_smb,      /* unknown SMB 0x79 */
  dissect_unknown_smb,      /* unknown SMB 0x7a */
  dissect_unknown_smb,      /* unknown SMB 0x7b */
  dissect_unknown_smb,      /* unknown SMB 0x7c */
  dissect_unknown_smb,      /* unknown SMB 0x7d */
  dissect_unknown_smb,      /* unknown SMB 0x7e */
  dissect_unknown_smb,      /* unknown SMB 0x7f */
  dissect_unknown_smb,
  dissect_search_dir_smb,   /* SMBsearch search a directory */
  dissect_unknown_smb,      /* SMBffirst find first */
  dissect_unknown_smb,      /* SMBfunique find unique */
  dissect_unknown_smb,      /* SMBfclose find close */
  dissect_unknown_smb,      /* unknown SMB 0x85 */
  dissect_unknown_smb,      /* unknown SMB 0x86 */
  dissect_unknown_smb,      /* unknown SMB 0x87 */
  dissect_unknown_smb,      /* unknown SMB 0x88 */
  dissect_unknown_smb,      /* unknown SMB 0x89 */
  dissect_unknown_smb,      /* unknown SMB 0x8a */
  dissect_unknown_smb,      /* unknown SMB 0x8b */
  dissect_unknown_smb,      /* unknown SMB 0x8c */
  dissect_unknown_smb,      /* unknown SMB 0x8d */
  dissect_unknown_smb,      /* unknown SMB 0x8e */
  dissect_unknown_smb,      /* unknown SMB 0x8f */
  dissect_unknown_smb,      /* unknown SMB 0x90 */
  dissect_unknown_smb,      /* unknown SMB 0x91 */
  dissect_unknown_smb,      /* unknown SMB 0x92 */
  dissect_unknown_smb,      /* unknown SMB 0x93 */
  dissect_unknown_smb,      /* unknown SMB 0x94 */
  dissect_unknown_smb,      /* unknown SMB 0x95 */
  dissect_unknown_smb,      /* unknown SMB 0x96 */
  dissect_unknown_smb,      /* unknown SMB 0x97 */
  dissect_unknown_smb,      /* unknown SMB 0x98 */
  dissect_unknown_smb,      /* unknown SMB 0x99 */
  dissect_unknown_smb,      /* unknown SMB 0x9a */
  dissect_unknown_smb,      /* unknown SMB 0x9b */
  dissect_unknown_smb,      /* unknown SMB 0x9c */
  dissect_unknown_smb,      /* unknown SMB 0x9d */
  dissect_unknown_smb,      /* unknown SMB 0x9e */
  dissect_unknown_smb,      /* unknown SMB 0x9f */
  dissect_unknown_smb,      /* unknown SMB 0xa0 */
  dissect_unknown_smb,      /* unknown SMB 0xa1 */
  dissect_unknown_smb,      /* unknown SMB 0xa2 */
  dissect_unknown_smb,      /* unknown SMB 0xa3 */
  dissect_unknown_smb,      /* unknown SMB 0xa4 */
  dissect_unknown_smb,      /* unknown SMB 0xa5 */
  dissect_unknown_smb,      /* unknown SMB 0xa6 */
  dissect_unknown_smb,      /* unknown SMB 0xa7 */
  dissect_unknown_smb,      /* unknown SMB 0xa8 */
  dissect_unknown_smb,      /* unknown SMB 0xa9 */
  dissect_unknown_smb,      /* unknown SMB 0xaa */
  dissect_unknown_smb,      /* unknown SMB 0xab */
  dissect_unknown_smb,      /* unknown SMB 0xac */
  dissect_unknown_smb,      /* unknown SMB 0xad */
  dissect_unknown_smb,      /* unknown SMB 0xae */
  dissect_unknown_smb,      /* unknown SMB 0xaf */
  dissect_unknown_smb,      /* unknown SMB 0xb0 */
  dissect_unknown_smb,      /* unknown SMB 0xb1 */
  dissect_unknown_smb,      /* unknown SMB 0xb2 */
  dissect_unknown_smb,      /* unknown SMB 0xb3 */
  dissect_unknown_smb,      /* unknown SMB 0xb4 */
  dissect_unknown_smb,      /* unknown SMB 0xb5 */
  dissect_unknown_smb,      /* unknown SMB 0xb6 */
  dissect_unknown_smb,      /* unknown SMB 0xb7 */
  dissect_unknown_smb,      /* unknown SMB 0xb8 */
  dissect_unknown_smb,      /* unknown SMB 0xb9 */
  dissect_unknown_smb,      /* unknown SMB 0xba */
  dissect_unknown_smb,      /* unknown SMB 0xbb */
  dissect_unknown_smb,      /* unknown SMB 0xbc */
  dissect_unknown_smb,      /* unknown SMB 0xbd */
  dissect_unknown_smb,      /* unknown SMB 0xbe */
  dissect_unknown_smb,      /* unknown SMB 0xbf */
  dissect_unknown_smb,      /* SMBsplopen open a print spool file */
  dissect_write_print_file_smb,/* SMBsplwr write to a print spool file */
  dissect_unknown_smb,
  dissect_get_print_queue_smb, /* SMBsplretq return print queue */
  dissect_unknown_smb,      /* unknown SMB 0xc4 */
  dissect_unknown_smb,      /* unknown SMB 0xc5 */
  dissect_unknown_smb,      /* unknown SMB 0xc6 */
  dissect_unknown_smb,      /* unknown SMB 0xc7 */
  dissect_unknown_smb,      /* unknown SMB 0xc8 */
  dissect_unknown_smb,      /* unknown SMB 0xc9 */
  dissect_unknown_smb,      /* unknown SMB 0xca */
  dissect_unknown_smb,      /* unknown SMB 0xcb */
  dissect_unknown_smb,      /* unknown SMB 0xcc */
  dissect_unknown_smb,      /* unknown SMB 0xcd */
  dissect_unknown_smb,      /* unknown SMB 0xce */
  dissect_unknown_smb,      /* unknown SMB 0xcf */
  dissect_unknown_smb,      /* SMBsends send a single block message */
  dissect_unknown_smb,      /* SMBsendb send a broadcast message */
  dissect_unknown_smb,      /* SMBfwdname forward user name */
  dissect_unknown_smb,      /* SMBcancelf cancel forward */
  dissect_unknown_smb,      /* SMBgetmac get a machine name */
  dissect_unknown_smb,      /* SMBsendstrt send start of multi-block message */
  dissect_unknown_smb,      /* SMBsendend send end of multi-block message */
  dissect_unknown_smb,      /* SMBsendtxt send text of multi-block message */
  dissect_unknown_smb,      /* unknown SMB 0xd8 */
  dissect_unknown_smb,      /* unknown SMB 0xd9 */
  dissect_unknown_smb,      /* unknown SMB 0xda */
  dissect_unknown_smb,      /* unknown SMB 0xdb */
  dissect_unknown_smb,      /* unknown SMB 0xdc */
  dissect_unknown_smb,      /* unknown SMB 0xdd */
  dissect_unknown_smb,      /* unknown SMB 0xde */
  dissect_unknown_smb,      /* unknown SMB 0xdf */
  dissect_unknown_smb,      /* unknown SMB 0xe0 */
  dissect_unknown_smb,      /* unknown SMB 0xe1 */
  dissect_unknown_smb,      /* unknown SMB 0xe2 */
  dissect_unknown_smb,      /* unknown SMB 0xe3 */
  dissect_unknown_smb,      /* unknown SMB 0xe4 */
  dissect_unknown_smb,      /* unknown SMB 0xe5 */
  dissect_unknown_smb,      /* unknown SMB 0xe6 */
  dissect_unknown_smb,      /* unknown SMB 0xe7 */
  dissect_unknown_smb,      /* unknown SMB 0xe8 */
  dissect_unknown_smb,      /* unknown SMB 0xe9 */
  dissect_unknown_smb,      /* unknown SMB 0xea */
  dissect_unknown_smb,      /* unknown SMB 0xeb */
  dissect_unknown_smb,      /* unknown SMB 0xec */
  dissect_unknown_smb,      /* unknown SMB 0xed */
  dissect_unknown_smb,      /* unknown SMB 0xee */
  dissect_unknown_smb,      /* unknown SMB 0xef */
  dissect_unknown_smb,      /* unknown SMB 0xf0 */
  dissect_unknown_smb,      /* unknown SMB 0xf1 */
  dissect_unknown_smb,      /* unknown SMB 0xf2 */
  dissect_unknown_smb,      /* unknown SMB 0xf3 */
  dissect_unknown_smb,      /* unknown SMB 0xf4 */
  dissect_unknown_smb,      /* unknown SMB 0xf5 */
  dissect_unknown_smb,      /* unknown SMB 0xf6 */
  dissect_unknown_smb,      /* unknown SMB 0xf7 */
  dissect_unknown_smb,      /* unknown SMB 0xf8 */
  dissect_unknown_smb,      /* unknown SMB 0xf9 */
  dissect_unknown_smb,      /* unknown SMB 0xfa */
  dissect_unknown_smb,      /* unknown SMB 0xfb */
  dissect_unknown_smb,      /* unknown SMB 0xfc */
  dissect_unknown_smb,      /* unknown SMB 0xfd */
  dissect_unknown_smb,      /* SMBinvalid invalid command */
  dissect_unknown_smb       /* unknown SMB 0xff */

};

static const value_string errcls_types[] = {
  { SMB_SUCCESS, "Success"},
  { SMB_ERRDOS, "DOS Error"},
  { SMB_ERRSRV, "Server Error"},
  { SMB_ERRHRD, "Hardware Error"},
  { SMB_ERRCMD, "Command Error - Not an SMB format command"},
  { 0, NULL }
};

static const value_string DOS_errors[] = {
  {SMBE_badfunc, "Invalid function (or system call)"},
  {SMBE_badfile, "File not found (pathname error)"},
  {SMBE_badpath, "Directory not found"},
  {SMBE_nofids, "Too many open files"},
  {SMBE_noaccess, "Access denied"},
  {SMBE_badfid, "Invalid fid"},
  {SMBE_nomem,  "Out of memory"},
  {SMBE_badmem, "Invalid memory block address"},
  {SMBE_badenv, "Invalid environment"},
  {SMBE_badaccess, "Invalid open mode"},
  {SMBE_baddata, "Invalid data (only from ioctl call)"},
  {SMBE_res, "Reserved error code?"}, 
  {SMBE_baddrive, "Invalid drive"},
  {SMBE_remcd, "Attempt to delete current directory"},
  {SMBE_diffdevice, "Rename/move across different filesystems"},
  {SMBE_nofiles, "no more files found in file search"},
  {SMBE_badshare, "Share mode on file conflict with open mode"},
  {SMBE_lock, "Lock request conflicts with existing lock"},
  {SMBE_unsup, "Request unsupported, returned by Win 95"},
  {SMBE_nosuchshare, "Requested share does not exist"},
  {SMBE_filexists, "File in operation already exists"},
  {SMBE_cannotopen, "Cannot open the file specified"},
  {SMBE_unknownlevel, "Unknown level??"},
  {SMBE_badpipe, "Named pipe invalid"},
  {SMBE_pipebusy, "All instances of pipe are busy"},
  {SMBE_pipeclosing, "Named pipe close in progress"},
  {SMBE_notconnected, "No process on other end of named pipe"},
  {SMBE_moredata, "More data to be returned"},
  {SMBE_baddirectory,  "Invalid directory name in a path."},
  {SMBE_eas_didnt_fit, "Extended attributes didn't fit"},
  {SMBE_eas_nsup, "Extended attributes not supported"},
  {SMBE_notify_buf_small, "Buffer too small to return change notify."},
  {SMBE_unknownipc, "Unknown IPC Operation"},
  {SMBE_noipc, "Don't support ipc"},
  {0, NULL}
  };

/* Error codes for the ERRSRV class */

static const value_string SRV_errors[] = {
  {SMBE_error, "Non specific error code"},
  {SMBE_badpw, "Bad password"},
  {SMBE_badtype, "Reserved"},
  {SMBE_access, "No permissions to perform the requested operation"},
  {SMBE_invnid, "TID invalid"},
  {SMBE_invnetname, "Invalid network name. Service not found"},
  {SMBE_invdevice, "Invalid device"},
  {SMBE_unknownsmb, "Unknown SMB, from NT 3.5 response"},
  {SMBE_qfull, "Print queue full"},
  {SMBE_qtoobig, "Queued item too big"},
  {SMBE_qeof, "EOF on print queue dump"},
  {SMBE_invpfid, "Invalid print file in smb_fid"},
  {SMBE_smbcmd, "Unrecognised command"},
  {SMBE_srverror, "SMB server internal error"},
  {SMBE_filespecs, "Fid and pathname invalid combination"},
  {SMBE_badlink, "Bad link in request ???"},
  {SMBE_badpermits, "Access specified for a file is not valid"},
  {SMBE_badpid, "Bad process id in request"},
  {SMBE_setattrmode, "Attribute mode invalid"},
  {SMBE_paused, "Message server paused"},
  {SMBE_msgoff, "Not receiving messages"},
  {SMBE_noroom, "No room for message"},
  {SMBE_rmuns, "Too many remote usernames"},
  {SMBE_timeout, "Operation timed out"},
  {SMBE_noresource, "No resources currently available for request."},
  {SMBE_toomanyuids, "Too many userids"},
  {SMBE_baduid, "Bad userid"},
  {SMBE_useMPX, "Temporarily unable to use raw mode, use MPX mode"},
  {SMBE_useSTD, "Temporarily unable to use raw mode, use standard mode"},
  {SMBE_contMPX, "Resume MPX mode"},
  {SMBE_badPW, "Bad Password???"},
  {SMBE_nosupport, "Operation not supported"},
  { 0, NULL}
};

/* Error codes for the ERRHRD class */

static const value_string HRD_errors[] = {
  {SMBE_nowrite, "read only media"},
  {SMBE_badunit, "Unknown device"},
  {SMBE_notready, "Drive not ready"},
  {SMBE_badcmd, "Unknown command"},
  {SMBE_data, "Data (CRC) error"},
  {SMBE_badreq, "Bad request structure length"},
  {SMBE_seek, "Seek error???"},
  {SMBE_badmedia, "Bad media???"},
  {SMBE_badsector, "Bad sector???"},
  {SMBE_nopaper, "No paper in printer???"},
  {SMBE_write, "Write error???"},
  {SMBE_read, "Read error???"},
  {SMBE_general, "General error???"},
  {SMBE_badshare, "A open conflicts with an existing open"},
  {SMBE_lock, "Lock/unlock error"},
  {SMBE_wrongdisk,  "Wrong disk???"},
  {SMBE_FCBunavail, "FCB unavailable???"},
  {SMBE_sharebufexc, "Share buffer excluded???"},
  {SMBE_diskfull, "Disk full???"},
  {0, NULL}
};

char *decode_smb_error(guint8 errcls, guint16 errcode)
{

  switch (errcls) {

  case SMB_SUCCESS:

    return("No Error");   /* No error ??? */
    break;

  case SMB_ERRDOS:

    return(val_to_str(errcode, DOS_errors, "Unknown DOS error (%x)"));
    break;

  case SMB_ERRSRV:

    return(val_to_str(errcode, SRV_errors, "Unknown SRV error (%x)"));
    break;

  case SMB_ERRHRD:

    return(val_to_str(errcode, HRD_errors, "Unknown HRD error (%x)"));
    break;

  default:

    return("Unknown error class!");

  }

}

/*
 * NT error codes.
 *
 * From
 *
 *	http://www.wildpackets.com/elements/SMB_NT_Status_Codes.txt
 */
static const value_string NT_errors[] = {
  { 0x00000000, "STATUS_SUCCESS" },
  { 0x00000000, "STATUS_WAIT_0" },
  { 0x00000001, "STATUS_WAIT_1" },
  { 0x00000002, "STATUS_WAIT_2" },
  { 0x00000003, "STATUS_WAIT_3" },
  { 0x0000003F, "STATUS_WAIT_63" },
  { 0x00000080, "STATUS_ABANDONED" },
  { 0x00000080, "STATUS_ABANDONED_WAIT_0" },
  { 0x000000BF, "STATUS_ABANDONED_WAIT_63" },
  { 0x000000C0, "STATUS_USER_APC" },
  { 0x00000100, "STATUS_KERNEL_APC" },
  { 0x00000101, "STATUS_ALERTED" },
  { 0x00000102, "STATUS_TIMEOUT" },
  { 0x00000103, "STATUS_PENDING" },
  { 0x00000104, "STATUS_REPARSE" },
  { 0x00000105, "STATUS_MORE_ENTRIES" },
  { 0x00000106, "STATUS_NOT_ALL_ASSIGNED" },
  { 0x00000107, "STATUS_SOME_NOT_MAPPED" },
  { 0x00000108, "STATUS_OPLOCK_BREAK_IN_PROGRESS" },
  { 0x00000109, "STATUS_VOLUME_MOUNTED" },
  { 0x0000010A, "STATUS_RXACT_COMMITTED" },
  { 0x0000010B, "STATUS_NOTIFY_CLEANUP" },
  { 0x0000010C, "STATUS_NOTIFY_ENUM_DIR" },
  { 0x0000010D, "STATUS_NO_QUOTAS_FOR_ACCOUNT" },
  { 0x0000010E, "STATUS_PRIMARY_TRANSPORT_CONNECT_FAILED" },
  { 0x00000110, "STATUS_PAGE_FAULT_TRANSITION" },
  { 0x00000111, "STATUS_PAGE_FAULT_DEMAND_ZERO" },
  { 0x00000112, "STATUS_PAGE_FAULT_COPY_ON_WRITE" },
  { 0x00000113, "STATUS_PAGE_FAULT_GUARD_PAGE" },
  { 0x00000114, "STATUS_PAGE_FAULT_PAGING_FILE" },
  { 0x00000115, "STATUS_CACHE_PAGE_LOCKED" },
  { 0x00000116, "STATUS_CRASH_DUMP" },
  { 0x00000117, "STATUS_BUFFER_ALL_ZEROS" },
  { 0x00000118, "STATUS_REPARSE_OBJECT" },
  { 0x40000000, "STATUS_OBJECT_NAME_EXISTS" },
  { 0x40000001, "STATUS_THREAD_WAS_SUSPENDED" },
  { 0x40000002, "STATUS_WORKING_SET_LIMIT_RANGE" },
  { 0x40000003, "STATUS_IMAGE_NOT_AT_BASE" },
  { 0x40000004, "STATUS_RXACT_STATE_CREATED" },
  { 0x40000005, "STATUS_SEGMENT_NOTIFICATION" },
  { 0x40000006, "STATUS_LOCAL_USER_SESSION_KEY" },
  { 0x40000007, "STATUS_BAD_CURRENT_DIRECTORY" },
  { 0x40000008, "STATUS_SERIAL_MORE_WRITES" },
  { 0x40000009, "STATUS_REGISTRY_RECOVERED" },
  { 0x4000000A, "STATUS_FT_READ_RECOVERY_FROM_BACKUP" },
  { 0x4000000B, "STATUS_FT_WRITE_RECOVERY" },
  { 0x4000000C, "STATUS_SERIAL_COUNTER_TIMEOUT" },
  { 0x4000000D, "STATUS_NULL_LM_PASSWORD" },
  { 0x4000000E, "STATUS_IMAGE_MACHINE_TYPE_MISMATCH" },
  { 0x4000000F, "STATUS_RECEIVE_PARTIAL" },
  { 0x40000010, "STATUS_RECEIVE_EXPEDITED" },
  { 0x40000011, "STATUS_RECEIVE_PARTIAL_EXPEDITED" },
  { 0x40000012, "STATUS_EVENT_DONE" },
  { 0x40000013, "STATUS_EVENT_PENDING" },
  { 0x40000014, "STATUS_CHECKING_FILE_SYSTEM" },
  { 0x40000015, "STATUS_FATAL_APP_EXIT" },
  { 0x40000016, "STATUS_PREDEFINED_HANDLE" },
  { 0x40000017, "STATUS_WAS_UNLOCKED" },
  { 0x40000018, "STATUS_SERVICE_NOTIFICATION" },
  { 0x40000019, "STATUS_WAS_LOCKED" },
  { 0x4000001A, "STATUS_LOG_HARD_ERROR" },
  { 0x4000001B, "STATUS_ALREADY_WIN32" },
  { 0x4000001C, "STATUS_WX86_UNSIMULATE" },
  { 0x4000001D, "STATUS_WX86_CONTINUE" },
  { 0x4000001E, "STATUS_WX86_SINGLE_STEP" },
  { 0x4000001F, "STATUS_WX86_BREAKPOINT" },
  { 0x40000020, "STATUS_WX86_EXCEPTION_CONTINUE" },
  { 0x40000021, "STATUS_WX86_EXCEPTION_LASTCHANCE" },
  { 0x40000022, "STATUS_WX86_EXCEPTION_CHAIN" },
  { 0x40000023, "STATUS_IMAGE_MACHINE_TYPE_MISMATCH_EXE" },
  { 0x40000024, "STATUS_NO_YIELD_PERFORMED" },
  { 0x40000025, "STATUS_TIMER_RESUME_IGNORED" },
  { 0x80000001, "STATUS_GUARD_PAGE_VIOLATION" },
  { 0x80000002, "STATUS_DATATYPE_MISALIGNMENT" },
  { 0x80000003, "STATUS_BREAKPOINT" },
  { 0x80000004, "STATUS_SINGLE_STEP" },
  { 0x80000005, "STATUS_BUFFER_OVERFLOW" },
  { 0x80000006, "STATUS_NO_MORE_FILES" },
  { 0x80000007, "STATUS_WAKE_SYSTEM_DEBUGGER" },
  { 0x8000000A, "STATUS_HANDLES_CLOSED" },
  { 0x8000000B, "STATUS_NO_INHERITANCE" },
  { 0x8000000C, "STATUS_GUID_SUBSTITUTION_MADE" },
  { 0x8000000D, "STATUS_PARTIAL_COPY" },
  { 0x8000000E, "STATUS_DEVICE_PAPER_EMPTY" },
  { 0x8000000F, "STATUS_DEVICE_POWERED_OFF" },
  { 0x80000010, "STATUS_DEVICE_OFF_LINE" },
  { 0x80000011, "STATUS_DEVICE_BUSY" },
  { 0x80000012, "STATUS_NO_MORE_EAS" },
  { 0x80000013, "STATUS_INVALID_EA_NAME" },
  { 0x80000014, "STATUS_EA_LIST_INCONSISTENT" },
  { 0x80000015, "STATUS_INVALID_EA_FLAG" },
  { 0x80000016, "STATUS_VERIFY_REQUIRED" },
  { 0x80000017, "STATUS_EXTRANEOUS_INFORMATION" },
  { 0x80000018, "STATUS_RXACT_COMMIT_NECESSARY" },
  { 0x8000001A, "STATUS_NO_MORE_ENTRIES" },
  { 0x8000001B, "STATUS_FILEMARK_DETECTED" },
  { 0x8000001C, "STATUS_MEDIA_CHANGED" },
  { 0x8000001D, "STATUS_BUS_RESET" },
  { 0x8000001E, "STATUS_END_OF_MEDIA" },
  { 0x8000001F, "STATUS_BEGINNING_OF_MEDIA" },
  { 0x80000020, "STATUS_MEDIA_CHECK" },
  { 0x80000021, "STATUS_SETMARK_DETECTED" },
  { 0x80000022, "STATUS_NO_DATA_DETECTED" },
  { 0x80000023, "STATUS_REDIRECTOR_HAS_OPEN_HANDLES" },
  { 0x80000024, "STATUS_SERVER_HAS_OPEN_HANDLES" },
  { 0x80000025, "STATUS_ALREADY_DISCONNECTED" },
  { 0x80000026, "STATUS_LONGJUMP" },
  { 0xC0000001, "STATUS_UNSUCCESSFUL" },
  { 0xC0000002, "STATUS_NOT_IMPLEMENTED" },
  { 0xC0000003, "STATUS_INVALID_INFO_CLASS" },
  { 0xC0000004, "STATUS_INFO_LENGTH_MISMATCH" },
  { 0xC0000005, "STATUS_ACCESS_VIOLATION" },
  { 0xC0000006, "STATUS_IN_PAGE_ERROR" },
  { 0xC0000007, "STATUS_PAGEFILE_QUOTA" },
  { 0xC0000008, "STATUS_INVALID_HANDLE" },
  { 0xC0000009, "STATUS_BAD_INITIAL_STACK" },
  { 0xC000000A, "STATUS_BAD_INITIAL_PC" },
  { 0xC000000B, "STATUS_INVALID_CID" },
  { 0xC000000C, "STATUS_TIMER_NOT_CANCELED" },
  { 0xC000000D, "STATUS_INVALID_PARAMETER" },
  { 0xC000000E, "STATUS_NO_SUCH_DEVICE" },
  { 0xC000000F, "STATUS_NO_SUCH_FILE" },
  { 0xC0000010, "STATUS_INVALID_DEVICE_REQUEST" },
  { 0xC0000011, "STATUS_END_OF_FILE" },
  { 0xC0000012, "STATUS_WRONG_VOLUME" },
  { 0xC0000013, "STATUS_NO_MEDIA_IN_DEVICE" },
  { 0xC0000014, "STATUS_UNRECOGNIZED_MEDIA" },
  { 0xC0000015, "STATUS_NONEXISTENT_SECTOR" },
  { 0xC0000016, "STATUS_MORE_PROCESSING_REQUIRED" },
  { 0xC0000017, "STATUS_NO_MEMORY" },
  { 0xC0000018, "STATUS_CONFLICTING_ADDRESSES" },
  { 0xC0000019, "STATUS_NOT_MAPPED_VIEW" },
  { 0xC000001A, "STATUS_UNABLE_TO_FREE_VM" },
  { 0xC000001B, "STATUS_UNABLE_TO_DELETE_SECTION" },
  { 0xC000001C, "STATUS_INVALID_SYSTEM_SERVICE" },
  { 0xC000001D, "STATUS_ILLEGAL_INSTRUCTION" },
  { 0xC000001E, "STATUS_INVALID_LOCK_SEQUENCE" },
  { 0xC000001F, "STATUS_INVALID_VIEW_SIZE" },
  { 0xC0000020, "STATUS_INVALID_FILE_FOR_SECTION" },
  { 0xC0000021, "STATUS_ALREADY_COMMITTED" },
  { 0xC0000022, "STATUS_ACCESS_DENIED" },
  { 0xC0000023, "STATUS_BUFFER_TOO_SMALL" },
  { 0xC0000024, "STATUS_OBJECT_TYPE_MISMATCH" },
  { 0xC0000025, "STATUS_NONCONTINUABLE_EXCEPTION" },
  { 0xC0000026, "STATUS_INVALID_DISPOSITION" },
  { 0xC0000027, "STATUS_UNWIND" },
  { 0xC0000028, "STATUS_BAD_STACK" },
  { 0xC0000029, "STATUS_INVALID_UNWIND_TARGET" },
  { 0xC000002A, "STATUS_NOT_LOCKED" },
  { 0xC000002B, "STATUS_PARITY_ERROR" },
  { 0xC000002C, "STATUS_UNABLE_TO_DECOMMIT_VM" },
  { 0xC000002D, "STATUS_NOT_COMMITTED" },
  { 0xC000002E, "STATUS_INVALID_PORT_ATTRIBUTES" },
  { 0xC000002F, "STATUS_PORT_MESSAGE_TOO_LONG" },
  { 0xC0000030, "STATUS_INVALID_PARAMETER_MIX" },
  { 0xC0000031, "STATUS_INVALID_QUOTA_LOWER" },
  { 0xC0000032, "STATUS_DISK_CORRUPT_ERROR" },
  { 0xC0000033, "STATUS_OBJECT_NAME_INVALID" },
  { 0xC0000034, "STATUS_OBJECT_NAME_NOT_FOUND" },
  { 0xC0000035, "STATUS_OBJECT_NAME_COLLISION" },
  { 0xC0000037, "STATUS_PORT_DISCONNECTED" },
  { 0xC0000038, "STATUS_DEVICE_ALREADY_ATTACHED" },
  { 0xC0000039, "STATUS_OBJECT_PATH_INVALID" },
  { 0xC000003A, "STATUS_OBJECT_PATH_NOT_FOUND" },
  { 0xC000003B, "STATUS_OBJECT_PATH_SYNTAX_BAD" },
  { 0xC000003C, "STATUS_DATA_OVERRUN" },
  { 0xC000003D, "STATUS_DATA_LATE_ERROR" },
  { 0xC000003E, "STATUS_DATA_ERROR" },
  { 0xC000003F, "STATUS_CRC_ERROR" },
  { 0xC0000040, "STATUS_SECTION_TOO_BIG" },
  { 0xC0000041, "STATUS_PORT_CONNECTION_REFUSED" },
  { 0xC0000042, "STATUS_INVALID_PORT_HANDLE" },
  { 0xC0000043, "STATUS_SHARING_VIOLATION" },
  { 0xC0000044, "STATUS_QUOTA_EXCEEDED" },
  { 0xC0000045, "STATUS_INVALID_PAGE_PROTECTION" },
  { 0xC0000046, "STATUS_MUTANT_NOT_OWNED" },
  { 0xC0000047, "STATUS_SEMAPHORE_LIMIT_EXCEEDED" },
  { 0xC0000048, "STATUS_PORT_ALREADY_SET" },
  { 0xC0000049, "STATUS_SECTION_NOT_IMAGE" },
  { 0xC000004A, "STATUS_SUSPEND_COUNT_EXCEEDED" },
  { 0xC000004B, "STATUS_THREAD_IS_TERMINATING" },
  { 0xC000004C, "STATUS_BAD_WORKING_SET_LIMIT" },
  { 0xC000004D, "STATUS_INCOMPATIBLE_FILE_MAP" },
  { 0xC000004E, "STATUS_SECTION_PROTECTION" },
  { 0xC000004F, "STATUS_EAS_NOT_SUPPORTED" },
  { 0xC0000050, "STATUS_EA_TOO_LARGE" },
  { 0xC0000051, "STATUS_NONEXISTENT_EA_ENTRY" },
  { 0xC0000052, "STATUS_NO_EAS_ON_FILE" },
  { 0xC0000053, "STATUS_EA_CORRUPT_ERROR" },
  { 0xC0000054, "STATUS_FILE_LOCK_CONFLICT" },
  { 0xC0000055, "STATUS_LOCK_NOT_GRANTED" },
  { 0xC0000056, "STATUS_DELETE_PENDING" },
  { 0xC0000057, "STATUS_CTL_FILE_NOT_SUPPORTED" },
  { 0xC0000058, "STATUS_UNKNOWN_REVISION" },
  { 0xC0000059, "STATUS_REVISION_MISMATCH" },
  { 0xC000005A, "STATUS_INVALID_OWNER" },
  { 0xC000005B, "STATUS_INVALID_PRIMARY_GROUP" },
  { 0xC000005C, "STATUS_NO_IMPERSONATION_TOKEN" },
  { 0xC000005D, "STATUS_CANT_DISABLE_MANDATORY" },
  { 0xC000005E, "STATUS_NO_LOGON_SERVERS" },
  { 0xC000005F, "STATUS_NO_SUCH_LOGON_SESSION" },
  { 0xC0000060, "STATUS_NO_SUCH_PRIVILEGE" },
  { 0xC0000061, "STATUS_PRIVILEGE_NOT_HELD" },
  { 0xC0000062, "STATUS_INVALID_ACCOUNT_NAME" },
  { 0xC0000063, "STATUS_USER_EXISTS" },
  { 0xC0000064, "STATUS_NO_SUCH_USER" },
  { 0xC0000065, "STATUS_GROUP_EXISTS" },
  { 0xC0000066, "STATUS_NO_SUCH_GROUP" },
  { 0xC0000067, "STATUS_MEMBER_IN_GROUP" },
  { 0xC0000068, "STATUS_MEMBER_NOT_IN_GROUP" },
  { 0xC0000069, "STATUS_LAST_ADMIN" },
  { 0xC000006A, "STATUS_WRONG_PASSWORD" },
  { 0xC000006B, "STATUS_ILL_FORMED_PASSWORD" },
  { 0xC000006C, "STATUS_PASSWORD_RESTRICTION" },
  { 0xC000006D, "STATUS_LOGON_FAILURE" },
  { 0xC000006E, "STATUS_ACCOUNT_RESTRICTION" },
  { 0xC000006F, "STATUS_INVALID_LOGON_HOURS" },
  { 0xC0000070, "STATUS_INVALID_WORKSTATION" },
  { 0xC0000071, "STATUS_PASSWORD_EXPIRED" },
  { 0xC0000072, "STATUS_ACCOUNT_DISABLED" },
  { 0xC0000073, "STATUS_NONE_MAPPED" },
  { 0xC0000074, "STATUS_TOO_MANY_LUIDS_REQUESTED" },
  { 0xC0000075, "STATUS_LUIDS_EXHAUSTED" },
  { 0xC0000076, "STATUS_INVALID_SUB_AUTHORITY" },
  { 0xC0000077, "STATUS_INVALID_ACL" },
  { 0xC0000078, "STATUS_INVALID_SID" },
  { 0xC0000079, "STATUS_INVALID_SECURITY_DESCR" },
  { 0xC000007A, "STATUS_PROCEDURE_NOT_FOUND" },
  { 0xC000007B, "STATUS_INVALID_IMAGE_FORMAT" },
  { 0xC000007C, "STATUS_NO_TOKEN" },
  { 0xC000007D, "STATUS_BAD_INHERITANCE_ACL" },
  { 0xC000007E, "STATUS_RANGE_NOT_LOCKED" },
  { 0xC000007F, "STATUS_DISK_FULL" },
  { 0xC0000080, "STATUS_SERVER_DISABLED" },
  { 0xC0000081, "STATUS_SERVER_NOT_DISABLED" },
  { 0xC0000082, "STATUS_TOO_MANY_GUIDS_REQUESTED" },
  { 0xC0000083, "STATUS_GUIDS_EXHAUSTED" },
  { 0xC0000084, "STATUS_INVALID_ID_AUTHORITY" },
  { 0xC0000085, "STATUS_AGENTS_EXHAUSTED" },
  { 0xC0000086, "STATUS_INVALID_VOLUME_LABEL" },
  { 0xC0000087, "STATUS_SECTION_NOT_EXTENDED" },
  { 0xC0000088, "STATUS_NOT_MAPPED_DATA" },
  { 0xC0000089, "STATUS_RESOURCE_DATA_NOT_FOUND" },
  { 0xC000008A, "STATUS_RESOURCE_TYPE_NOT_FOUND" },
  { 0xC000008B, "STATUS_RESOURCE_NAME_NOT_FOUND" },
  { 0xC000008C, "STATUS_ARRAY_BOUNDS_EXCEEDED" },
  { 0xC000008D, "STATUS_FLOAT_DENORMAL_OPERAND" },
  { 0xC000008E, "STATUS_FLOAT_DIVIDE_BY_ZERO" },
  { 0xC000008F, "STATUS_FLOAT_INEXACT_RESULT" },
  { 0xC0000090, "STATUS_FLOAT_INVALID_OPERATION" },
  { 0xC0000091, "STATUS_FLOAT_OVERFLOW" },
  { 0xC0000092, "STATUS_FLOAT_STACK_CHECK" },
  { 0xC0000093, "STATUS_FLOAT_UNDERFLOW" },
  { 0xC0000094, "STATUS_INTEGER_DIVIDE_BY_ZERO" },
  { 0xC0000095, "STATUS_INTEGER_OVERFLOW" },
  { 0xC0000096, "STATUS_PRIVILEGED_INSTRUCTION" },
  { 0xC0000097, "STATUS_TOO_MANY_PAGING_FILES" },
  { 0xC0000098, "STATUS_FILE_INVALID" },
  { 0xC0000099, "STATUS_ALLOTTED_SPACE_EXCEEDED" },
  { 0xC000009A, "STATUS_INSUFFICIENT_RESOURCES" },
  { 0xC000009B, "STATUS_DFS_EXIT_PATH_FOUND" },
  { 0xC000009C, "STATUS_DEVICE_DATA_ERROR" },
  { 0xC000009D, "STATUS_DEVICE_NOT_CONNECTED" },
  { 0xC000009E, "STATUS_DEVICE_POWER_FAILURE" },
  { 0xC000009F, "STATUS_FREE_VM_NOT_AT_BASE" },
  { 0xC00000A0, "STATUS_MEMORY_NOT_ALLOCATED" },
  { 0xC00000A1, "STATUS_WORKING_SET_QUOTA" },
  { 0xC00000A2, "STATUS_MEDIA_WRITE_PROTECTED" },
  { 0xC00000A3, "STATUS_DEVICE_NOT_READY" },
  { 0xC00000A4, "STATUS_INVALID_GROUP_ATTRIBUTES" },
  { 0xC00000A5, "STATUS_BAD_IMPERSONATION_LEVEL" },
  { 0xC00000A6, "STATUS_CANT_OPEN_ANONYMOUS" },
  { 0xC00000A7, "STATUS_BAD_VALIDATION_CLASS" },
  { 0xC00000A8, "STATUS_BAD_TOKEN_TYPE" },
  { 0xC00000A9, "STATUS_BAD_MASTER_BOOT_RECORD" },
  { 0xC00000AA, "STATUS_INSTRUCTION_MISALIGNMENT" },
  { 0xC00000AB, "STATUS_INSTANCE_NOT_AVAILABLE" },
  { 0xC00000AC, "STATUS_PIPE_NOT_AVAILABLE" },
  { 0xC00000AD, "STATUS_INVALID_PIPE_STATE" },
  { 0xC00000AE, "STATUS_PIPE_BUSY" },
  { 0xC00000AF, "STATUS_ILLEGAL_FUNCTION" },
  { 0xC00000B0, "STATUS_PIPE_DISCONNECTED" },
  { 0xC00000B1, "STATUS_PIPE_CLOSING" },
  { 0xC00000B2, "STATUS_PIPE_CONNECTED" },
  { 0xC00000B3, "STATUS_PIPE_LISTENING" },
  { 0xC00000B4, "STATUS_INVALID_READ_MODE" },
  { 0xC00000B5, "STATUS_IO_TIMEOUT" },
  { 0xC00000B6, "STATUS_FILE_FORCED_CLOSED" },
  { 0xC00000B7, "STATUS_PROFILING_NOT_STARTED" },
  { 0xC00000B8, "STATUS_PROFILING_NOT_STOPPED" },
  { 0xC00000B9, "STATUS_COULD_NOT_INTERPRET" },
  { 0xC00000BA, "STATUS_FILE_IS_A_DIRECTORY" },
  { 0xC00000BB, "STATUS_NOT_SUPPORTED" },
  { 0xC00000BC, "STATUS_REMOTE_NOT_LISTENING" },
  { 0xC00000BD, "STATUS_DUPLICATE_NAME" },
  { 0xC00000BE, "STATUS_BAD_NETWORK_PATH" },
  { 0xC00000BF, "STATUS_NETWORK_BUSY" },
  { 0xC00000C0, "STATUS_DEVICE_DOES_NOT_EXIST" },
  { 0xC00000C1, "STATUS_TOO_MANY_COMMANDS" },
  { 0xC00000C2, "STATUS_ADAPTER_HARDWARE_ERROR" },
  { 0xC00000C3, "STATUS_INVALID_NETWORK_RESPONSE" },
  { 0xC00000C4, "STATUS_UNEXPECTED_NETWORK_ERROR" },
  { 0xC00000C5, "STATUS_BAD_REMOTE_ADAPTER" },
  { 0xC00000C6, "STATUS_PRINT_QUEUE_FULL" },
  { 0xC00000C7, "STATUS_NO_SPOOL_SPACE" },
  { 0xC00000C8, "STATUS_PRINT_CANCELLED" },
  { 0xC00000C9, "STATUS_NETWORK_NAME_DELETED" },
  { 0xC00000CA, "STATUS_NETWORK_ACCESS_DENIED" },
  { 0xC00000CB, "STATUS_BAD_DEVICE_TYPE" },
  { 0xC00000CC, "STATUS_BAD_NETWORK_NAME" },
  { 0xC00000CD, "STATUS_TOO_MANY_NAMES" },
  { 0xC00000CE, "STATUS_TOO_MANY_SESSIONS" },
  { 0xC00000CF, "STATUS_SHARING_PAUSED" },
  { 0xC00000D0, "STATUS_REQUEST_NOT_ACCEPTED" },
  { 0xC00000D1, "STATUS_REDIRECTOR_PAUSED" },
  { 0xC00000D2, "STATUS_NET_WRITE_FAULT" },
  { 0xC00000D3, "STATUS_PROFILING_AT_LIMIT" },
  { 0xC00000D4, "STATUS_NOT_SAME_DEVICE" },
  { 0xC00000D5, "STATUS_FILE_RENAMED" },
  { 0xC00000D6, "STATUS_VIRTUAL_CIRCUIT_CLOSED" },
  { 0xC00000D7, "STATUS_NO_SECURITY_ON_OBJECT" },
  { 0xC00000D8, "STATUS_CANT_WAIT" },
  { 0xC00000D9, "STATUS_PIPE_EMPTY" },
  { 0xC00000DA, "STATUS_CANT_ACCESS_DOMAIN_INFO" },
  { 0xC00000DB, "STATUS_CANT_TERMINATE_SELF" },
  { 0xC00000DC, "STATUS_INVALID_SERVER_STATE" },
  { 0xC00000DD, "STATUS_INVALID_DOMAIN_STATE" },
  { 0xC00000DE, "STATUS_INVALID_DOMAIN_ROLE" },
  { 0xC00000DF, "STATUS_NO_SUCH_DOMAIN" },
  { 0xC00000E0, "STATUS_DOMAIN_EXISTS" },
  { 0xC00000E1, "STATUS_DOMAIN_LIMIT_EXCEEDED" },
  { 0xC00000E2, "STATUS_OPLOCK_NOT_GRANTED" },
  { 0xC00000E3, "STATUS_INVALID_OPLOCK_PROTOCOL" },
  { 0xC00000E4, "STATUS_INTERNAL_DB_CORRUPTION" },
  { 0xC00000E5, "STATUS_INTERNAL_ERROR" },
  { 0xC00000E6, "STATUS_GENERIC_NOT_MAPPED" },
  { 0xC00000E7, "STATUS_BAD_DESCRIPTOR_FORMAT" },
  { 0xC00000E8, "STATUS_INVALID_USER_BUFFER" },
  { 0xC00000E9, "STATUS_UNEXPECTED_IO_ERROR" },
  { 0xC00000EA, "STATUS_UNEXPECTED_MM_CREATE_ERR" },
  { 0xC00000EB, "STATUS_UNEXPECTED_MM_MAP_ERROR" },
  { 0xC00000EC, "STATUS_UNEXPECTED_MM_EXTEND_ERR" },
  { 0xC00000ED, "STATUS_NOT_LOGON_PROCESS" },
  { 0xC00000EE, "STATUS_LOGON_SESSION_EXISTS" },
  { 0xC00000EF, "STATUS_INVALID_PARAMETER_1" },
  { 0xC00000F0, "STATUS_INVALID_PARAMETER_2" },
  { 0xC00000F1, "STATUS_INVALID_PARAMETER_3" },
  { 0xC00000F2, "STATUS_INVALID_PARAMETER_4" },
  { 0xC00000F3, "STATUS_INVALID_PARAMETER_5" },
  { 0xC00000F4, "STATUS_INVALID_PARAMETER_6" },
  { 0xC00000F5, "STATUS_INVALID_PARAMETER_7" },
  { 0xC00000F6, "STATUS_INVALID_PARAMETER_8" },
  { 0xC00000F7, "STATUS_INVALID_PARAMETER_9" },
  { 0xC00000F8, "STATUS_INVALID_PARAMETER_10" },
  { 0xC00000F9, "STATUS_INVALID_PARAMETER_11" },
  { 0xC00000FA, "STATUS_INVALID_PARAMETER_12" },
  { 0xC00000FB, "STATUS_REDIRECTOR_NOT_STARTED" },
  { 0xC00000FC, "STATUS_REDIRECTOR_STARTED" },
  { 0xC00000FD, "STATUS_STACK_OVERFLOW" },
  { 0xC00000FE, "STATUS_NO_SUCH_PACKAGE" },
  { 0xC00000FF, "STATUS_BAD_FUNCTION_TABLE" },
  { 0xC0000100, "STATUS_VARIABLE_NOT_FOUND" },
  { 0xC0000101, "STATUS_DIRECTORY_NOT_EMPTY" },
  { 0xC0000102, "STATUS_FILE_CORRUPT_ERROR" },
  { 0xC0000103, "STATUS_NOT_A_DIRECTORY" },
  { 0xC0000104, "STATUS_BAD_LOGON_SESSION_STATE" },
  { 0xC0000105, "STATUS_LOGON_SESSION_COLLISION" },
  { 0xC0000106, "STATUS_NAME_TOO_LONG" },
  { 0xC0000107, "STATUS_FILES_OPEN" },
  { 0xC0000108, "STATUS_CONNECTION_IN_USE" },
  { 0xC0000109, "STATUS_MESSAGE_NOT_FOUND" },
  { 0xC000010A, "STATUS_PROCESS_IS_TERMINATING" },
  { 0xC000010B, "STATUS_INVALID_LOGON_TYPE" },
  { 0xC000010C, "STATUS_NO_GUID_TRANSLATION" },
  { 0xC000010D, "STATUS_CANNOT_IMPERSONATE" },
  { 0xC000010E, "STATUS_IMAGE_ALREADY_LOADED" },
  { 0xC000010F, "STATUS_ABIOS_NOT_PRESENT" },
  { 0xC0000110, "STATUS_ABIOS_LID_NOT_EXIST" },
  { 0xC0000111, "STATUS_ABIOS_LID_ALREADY_OWNED" },
  { 0xC0000112, "STATUS_ABIOS_NOT_LID_OWNER" },
  { 0xC0000113, "STATUS_ABIOS_INVALID_COMMAND" },
  { 0xC0000114, "STATUS_ABIOS_INVALID_LID" },
  { 0xC0000115, "STATUS_ABIOS_SELECTOR_NOT_AVAILABLE" },
  { 0xC0000116, "STATUS_ABIOS_INVALID_SELECTOR" },
  { 0xC0000117, "STATUS_NO_LDT" },
  { 0xC0000118, "STATUS_INVALID_LDT_SIZE" },
  { 0xC0000119, "STATUS_INVALID_LDT_OFFSET" },
  { 0xC000011A, "STATUS_INVALID_LDT_DESCRIPTOR" },
  { 0xC000011B, "STATUS_INVALID_IMAGE_NE_FORMAT" },
  { 0xC000011C, "STATUS_RXACT_INVALID_STATE" },
  { 0xC000011D, "STATUS_RXACT_COMMIT_FAILURE" },
  { 0xC000011E, "STATUS_MAPPED_FILE_SIZE_ZERO" },
  { 0xC000011F, "STATUS_TOO_MANY_OPENED_FILES" },
  { 0xC0000120, "STATUS_CANCELLED" },
  { 0xC0000121, "STATUS_CANNOT_DELETE" },
  { 0xC0000122, "STATUS_INVALID_COMPUTER_NAME" },
  { 0xC0000123, "STATUS_FILE_DELETED" },
  { 0xC0000124, "STATUS_SPECIAL_ACCOUNT" },
  { 0xC0000125, "STATUS_SPECIAL_GROUP" },
  { 0xC0000126, "STATUS_SPECIAL_USER" },
  { 0xC0000127, "STATUS_MEMBERS_PRIMARY_GROUP" },
  { 0xC0000128, "STATUS_FILE_CLOSED" },
  { 0xC0000129, "STATUS_TOO_MANY_THREADS" },
  { 0xC000012A, "STATUS_THREAD_NOT_IN_PROCESS" },
  { 0xC000012B, "STATUS_TOKEN_ALREADY_IN_USE" },
  { 0xC000012C, "STATUS_PAGEFILE_QUOTA_EXCEEDED" },
  { 0xC000012D, "STATUS_COMMITMENT_LIMIT" },
  { 0xC000012E, "STATUS_INVALID_IMAGE_LE_FORMAT" },
  { 0xC000012F, "STATUS_INVALID_IMAGE_NOT_MZ" },
  { 0xC0000130, "STATUS_INVALID_IMAGE_PROTECT" },
  { 0xC0000131, "STATUS_INVALID_IMAGE_WIN_16" },
  { 0xC0000132, "STATUS_LOGON_SERVER_CONFLICT" },
  { 0xC0000133, "STATUS_TIME_DIFFERENCE_AT_DC" },
  { 0xC0000134, "STATUS_SYNCHRONIZATION_REQUIRED" },
  { 0xC0000135, "STATUS_DLL_NOT_FOUND" },
  { 0xC0000136, "STATUS_OPEN_FAILED" },
  { 0xC0000137, "STATUS_IO_PRIVILEGE_FAILED" },
  { 0xC0000138, "STATUS_ORDINAL_NOT_FOUND" },
  { 0xC0000139, "STATUS_ENTRYPOINT_NOT_FOUND" },
  { 0xC000013A, "STATUS_CONTROL_C_EXIT" },
  { 0xC000013B, "STATUS_LOCAL_DISCONNECT" },
  { 0xC000013C, "STATUS_REMOTE_DISCONNECT" },
  { 0xC000013D, "STATUS_REMOTE_RESOURCES" },
  { 0xC000013E, "STATUS_LINK_FAILED" },
  { 0xC000013F, "STATUS_LINK_TIMEOUT" },
  { 0xC0000140, "STATUS_INVALID_CONNECTION" },
  { 0xC0000141, "STATUS_INVALID_ADDRESS" },
  { 0xC0000142, "STATUS_DLL_INIT_FAILED" },
  { 0xC0000143, "STATUS_MISSING_SYSTEMFILE" },
  { 0xC0000144, "STATUS_UNHANDLED_EXCEPTION" },
  { 0xC0000145, "STATUS_APP_INIT_FAILURE" },
  { 0xC0000146, "STATUS_PAGEFILE_CREATE_FAILED" },
  { 0xC0000147, "STATUS_NO_PAGEFILE" },
  { 0xC0000148, "STATUS_INVALID_LEVEL" },
  { 0xC0000149, "STATUS_WRONG_PASSWORD_CORE" },
  { 0xC000014A, "STATUS_ILLEGAL_FLOAT_CONTEXT" },
  { 0xC000014B, "STATUS_PIPE_BROKEN" },
  { 0xC000014C, "STATUS_REGISTRY_CORRUPT" },
  { 0xC000014D, "STATUS_REGISTRY_IO_FAILED" },
  { 0xC000014E, "STATUS_NO_EVENT_PAIR" },
  { 0xC000014F, "STATUS_UNRECOGNIZED_VOLUME" },
  { 0xC0000150, "STATUS_SERIAL_NO_DEVICE_INITED" },
  { 0xC0000151, "STATUS_NO_SUCH_ALIAS" },
  { 0xC0000152, "STATUS_MEMBER_NOT_IN_ALIAS" },
  { 0xC0000153, "STATUS_MEMBER_IN_ALIAS" },
  { 0xC0000154, "STATUS_ALIAS_EXISTS" },
  { 0xC0000155, "STATUS_LOGON_NOT_GRANTED" },
  { 0xC0000156, "STATUS_TOO_MANY_SECRETS" },
  { 0xC0000157, "STATUS_SECRET_TOO_LONG" },
  { 0xC0000158, "STATUS_INTERNAL_DB_ERROR" },
  { 0xC0000159, "STATUS_FULLSCREEN_MODE" },
  { 0xC000015A, "STATUS_TOO_MANY_CONTEXT_IDS" },
  { 0xC000015B, "STATUS_LOGON_TYPE_NOT_GRANTED" },
  { 0xC000015C, "STATUS_NOT_REGISTRY_FILE" },
  { 0xC000015D, "STATUS_NT_CROSS_ENCRYPTION_REQUIRED" },
  { 0xC000015E, "STATUS_DOMAIN_CTRLR_CONFIG_ERROR" },
  { 0xC000015F, "STATUS_FT_MISSING_MEMBER" },
  { 0xC0000160, "STATUS_ILL_FORMED_SERVICE_ENTRY" },
  { 0xC0000161, "STATUS_ILLEGAL_CHARACTER" },
  { 0xC0000162, "STATUS_UNMAPPABLE_CHARACTER" },
  { 0xC0000163, "STATUS_UNDEFINED_CHARACTER" },
  { 0xC0000164, "STATUS_FLOPPY_VOLUME" },
  { 0xC0000165, "STATUS_FLOPPY_ID_MARK_NOT_FOUND" },
  { 0xC0000166, "STATUS_FLOPPY_WRONG_CYLINDER" },
  { 0xC0000167, "STATUS_FLOPPY_UNKNOWN_ERROR" },
  { 0xC0000168, "STATUS_FLOPPY_BAD_REGISTERS" },
  { 0xC0000169, "STATUS_DISK_RECALIBRATE_FAILED" },
  { 0xC000016A, "STATUS_DISK_OPERATION_FAILED" },
  { 0xC000016B, "STATUS_DISK_RESET_FAILED" },
  { 0xC000016C, "STATUS_SHARED_IRQ_BUSY" },
  { 0xC000016D, "STATUS_FT_ORPHANING" },
  { 0xC000016E, "STATUS_BIOS_FAILED_TO_CONNECT_INTERRUPT" },
  { 0xC0000172, "STATUS_PARTITION_FAILURE" },
  { 0xC0000173, "STATUS_INVALID_BLOCK_LENGTH" },
  { 0xC0000174, "STATUS_DEVICE_NOT_PARTITIONED" },
  { 0xC0000175, "STATUS_UNABLE_TO_LOCK_MEDIA" },
  { 0xC0000176, "STATUS_UNABLE_TO_UNLOAD_MEDIA" },
  { 0xC0000177, "STATUS_EOM_OVERFLOW" },
  { 0xC0000178, "STATUS_NO_MEDIA" },
  { 0xC000017A, "STATUS_NO_SUCH_MEMBER" },
  { 0xC000017B, "STATUS_INVALID_MEMBER" },
  { 0xC000017C, "STATUS_KEY_DELETED" },
  { 0xC000017D, "STATUS_NO_LOG_SPACE" },
  { 0xC000017E, "STATUS_TOO_MANY_SIDS" },
  { 0xC000017F, "STATUS_LM_CROSS_ENCRYPTION_REQUIRED" },
  { 0xC0000180, "STATUS_KEY_HAS_CHILDREN" },
  { 0xC0000181, "STATUS_CHILD_MUST_BE_VOLATILE" },
  { 0xC0000182, "STATUS_DEVICE_CONFIGURATION_ERROR" },
  { 0xC0000183, "STATUS_DRIVER_INTERNAL_ERROR" },
  { 0xC0000184, "STATUS_INVALID_DEVICE_STATE" },
  { 0xC0000185, "STATUS_IO_DEVICE_ERROR" },
  { 0xC0000186, "STATUS_DEVICE_PROTOCOL_ERROR" },
  { 0xC0000187, "STATUS_BACKUP_CONTROLLER" },
  { 0xC0000188, "STATUS_LOG_FILE_FULL" },
  { 0xC0000189, "STATUS_TOO_LATE" },
  { 0xC000018A, "STATUS_NO_TRUST_LSA_SECRET" },
  { 0xC000018B, "STATUS_NO_TRUST_SAM_ACCOUNT" },
  { 0xC000018C, "STATUS_TRUSTED_DOMAIN_FAILURE" },
  { 0xC000018D, "STATUS_TRUSTED_RELATIONSHIP_FAILURE" },
  { 0xC000018E, "STATUS_EVENTLOG_FILE_CORRUPT" },
  { 0xC000018F, "STATUS_EVENTLOG_CANT_START" },
  { 0xC0000190, "STATUS_TRUST_FAILURE" },
  { 0xC0000191, "STATUS_MUTANT_LIMIT_EXCEEDED" },
  { 0xC0000192, "STATUS_NETLOGON_NOT_STARTED" },
  { 0xC0000193, "STATUS_ACCOUNT_EXPIRED" },
  { 0xC0000194, "STATUS_POSSIBLE_DEADLOCK" },
  { 0xC0000195, "STATUS_NETWORK_CREDENTIAL_CONFLICT" },
  { 0xC0000196, "STATUS_REMOTE_SESSION_LIMIT" },
  { 0xC0000197, "STATUS_EVENTLOG_FILE_CHANGED" },
  { 0xC0000198, "STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT" },
  { 0xC0000199, "STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT" },
  { 0xC000019A, "STATUS_NOLOGON_SERVER_TRUST_ACCOUNT" },
  { 0xC000019B, "STATUS_DOMAIN_TRUST_INCONSISTENT" },
  { 0xC000019C, "STATUS_FS_DRIVER_REQUIRED" },
  { 0xC0000202, "STATUS_NO_USER_SESSION_KEY" },
  { 0xC0000203, "STATUS_USER_SESSION_DELETED" },
  { 0xC0000204, "STATUS_RESOURCE_LANG_NOT_FOUND" },
  { 0xC0000205, "STATUS_INSUFF_SERVER_RESOURCES" },
  { 0xC0000206, "STATUS_INVALID_BUFFER_SIZE" },
  { 0xC0000207, "STATUS_INVALID_ADDRESS_COMPONENT" },
  { 0xC0000208, "STATUS_INVALID_ADDRESS_WILDCARD" },
  { 0xC0000209, "STATUS_TOO_MANY_ADDRESSES" },
  { 0xC000020A, "STATUS_ADDRESS_ALREADY_EXISTS" },
  { 0xC000020B, "STATUS_ADDRESS_CLOSED" },
  { 0xC000020C, "STATUS_CONNECTION_DISCONNECTED" },
  { 0xC000020D, "STATUS_CONNECTION_RESET" },
  { 0xC000020E, "STATUS_TOO_MANY_NODES" },
  { 0xC000020F, "STATUS_TRANSACTION_ABORTED" },
  { 0xC0000210, "STATUS_TRANSACTION_TIMED_OUT" },
  { 0xC0000211, "STATUS_TRANSACTION_NO_RELEASE" },
  { 0xC0000212, "STATUS_TRANSACTION_NO_MATCH" },
  { 0xC0000213, "STATUS_TRANSACTION_RESPONDED" },
  { 0xC0000214, "STATUS_TRANSACTION_INVALID_ID" },
  { 0xC0000215, "STATUS_TRANSACTION_INVALID_TYPE" },
  { 0xC0000216, "STATUS_NOT_SERVER_SESSION" },
  { 0xC0000217, "STATUS_NOT_CLIENT_SESSION" },
  { 0xC0000218, "STATUS_CANNOT_LOAD_REGISTRY_FILE" },
  { 0xC0000219, "STATUS_DEBUG_ATTACH_FAILED" },
  { 0xC000021A, "STATUS_SYSTEM_PROCESS_TERMINATED" },
  { 0xC000021B, "STATUS_DATA_NOT_ACCEPTED" },
  { 0xC000021C, "STATUS_NO_BROWSER_SERVERS_FOUND" },
  { 0xC000021D, "STATUS_VDM_HARD_ERROR" },
  { 0xC000021E, "STATUS_DRIVER_CANCEL_TIMEOUT" },
  { 0xC000021F, "STATUS_REPLY_MESSAGE_MISMATCH" },
  { 0xC0000220, "STATUS_MAPPED_ALIGNMENT" },
  { 0xC0000221, "STATUS_IMAGE_CHECKSUM_MISMATCH" },
  { 0xC0000222, "STATUS_LOST_WRITEBEHIND_DATA" },
  { 0xC0000223, "STATUS_CLIENT_SERVER_PARAMETERS_INVALID" },
  { 0xC0000224, "STATUS_PASSWORD_MUST_CHANGE" },
  { 0xC0000225, "STATUS_NOT_FOUND" },
  { 0xC0000226, "STATUS_NOT_TINY_STREAM" },
  { 0xC0000227, "STATUS_RECOVERY_FAILURE" },
  { 0xC0000228, "STATUS_STACK_OVERFLOW_READ" },
  { 0xC0000229, "STATUS_FAIL_CHECK" },
  { 0xC000022A, "STATUS_DUPLICATE_OBJECTID" },
  { 0xC000022B, "STATUS_OBJECTID_EXISTS" },
  { 0xC000022C, "STATUS_CONVERT_TO_LARGE" },
  { 0xC000022D, "STATUS_RETRY" },
  { 0xC000022E, "STATUS_FOUND_OUT_OF_SCOPE" },
  { 0xC000022F, "STATUS_ALLOCATE_BUCKET" },
  { 0xC0000230, "STATUS_PROPSET_NOT_FOUND" },
  { 0xC0000231, "STATUS_MARSHALL_OVERFLOW" },
  { 0xC0000232, "STATUS_INVALID_VARIANT" },
  { 0xC0000233, "STATUS_DOMAIN_CONTROLLER_NOT_FOUND" },
  { 0xC0000234, "STATUS_ACCOUNT_LOCKED_OUT" },
  { 0xC0000235, "STATUS_HANDLE_NOT_CLOSABLE" },
  { 0xC0000236, "STATUS_CONNECTION_REFUSED" },
  { 0xC0000237, "STATUS_GRACEFUL_DISCONNECT" },
  { 0xC0000238, "STATUS_ADDRESS_ALREADY_ASSOCIATED" },
  { 0xC0000239, "STATUS_ADDRESS_NOT_ASSOCIATED" },
  { 0xC000023A, "STATUS_CONNECTION_INVALID" },
  { 0xC000023B, "STATUS_CONNECTION_ACTIVE" },
  { 0xC000023C, "STATUS_NETWORK_UNREACHABLE" },
  { 0xC000023D, "STATUS_HOST_UNREACHABLE" },
  { 0xC000023E, "STATUS_PROTOCOL_UNREACHABLE" },
  { 0xC000023F, "STATUS_PORT_UNREACHABLE" },
  { 0xC0000240, "STATUS_REQUEST_ABORTED" },
  { 0xC0000241, "STATUS_CONNECTION_ABORTED" },
  { 0xC0000242, "STATUS_BAD_COMPRESSION_BUFFER" },
  { 0xC0000243, "STATUS_USER_MAPPED_FILE" },
  { 0xC0000244, "STATUS_AUDIT_FAILED" },
  { 0xC0000245, "STATUS_TIMER_RESOLUTION_NOT_SET" },
  { 0xC0000246, "STATUS_CONNECTION_COUNT_LIMIT" },
  { 0xC0000247, "STATUS_LOGIN_TIME_RESTRICTION" },
  { 0xC0000248, "STATUS_LOGIN_WKSTA_RESTRICTION" },
  { 0xC0000249, "STATUS_IMAGE_MP_UP_MISMATCH" },
  { 0xC0000250, "STATUS_INSUFFICIENT_LOGON_INFO" },
  { 0xC0000251, "STATUS_BAD_DLL_ENTRYPOINT" },
  { 0xC0000252, "STATUS_BAD_SERVICE_ENTRYPOINT" },
  { 0xC0000253, "STATUS_LPC_REPLY_LOST" },
  { 0xC0000254, "STATUS_IP_ADDRESS_CONFLICT1" },
  { 0xC0000255, "STATUS_IP_ADDRESS_CONFLICT2" },
  { 0xC0000256, "STATUS_REGISTRY_QUOTA_LIMIT" },
  { 0xC0000257, "STATUS_PATH_NOT_COVERED" },
  { 0xC0000258, "STATUS_NO_CALLBACK_ACTIVE" },
  { 0xC0000259, "STATUS_LICENSE_QUOTA_EXCEEDED" },
  { 0xC000025A, "STATUS_PWD_TOO_SHORT" },
  { 0xC000025B, "STATUS_PWD_TOO_RECENT" },
  { 0xC000025C, "STATUS_PWD_HISTORY_CONFLICT" },
  { 0xC000025E, "STATUS_PLUGPLAY_NO_DEVICE" },
  { 0xC000025F, "STATUS_UNSUPPORTED_COMPRESSION" },
  { 0xC0000260, "STATUS_INVALID_HW_PROFILE" },
  { 0xC0000261, "STATUS_INVALID_PLUGPLAY_DEVICE_PATH" },
  { 0xC0000262, "STATUS_DRIVER_ORDINAL_NOT_FOUND" },
  { 0xC0000263, "STATUS_DRIVER_ENTRYPOINT_NOT_FOUND" },
  { 0xC0000264, "STATUS_RESOURCE_NOT_OWNED" },
  { 0xC0000265, "STATUS_TOO_MANY_LINKS" },
  { 0xC0000266, "STATUS_QUOTA_LIST_INCONSISTENT" },
  { 0xC0000267, "STATUS_FILE_IS_OFFLINE" },
  { 0xC0000268, "STATUS_EVALUATION_EXPIRATION" },
  { 0xC0000269, "STATUS_ILLEGAL_DLL_RELOCATION" },
  { 0xC000026A, "STATUS_LICENSE_VIOLATION" },
  { 0xC000026B, "STATUS_DLL_INIT_FAILED_LOGOFF" },
  { 0xC000026C, "STATUS_DRIVER_UNABLE_TO_LOAD" },
  { 0xC000026D, "STATUS_DFS_UNAVAILABLE" },
  { 0xC000026E, "STATUS_VOLUME_DISMOUNTED" },
  { 0xC000026F, "STATUS_WX86_INTERNAL_ERROR" },
  { 0xC0000270, "STATUS_WX86_FLOAT_STACK_CHECK" },
  { 0xC0009898, "STATUS_WOW_ASSERTION" },
  { 0xC0020001, "RPC_NT_INVALID_STRING_BINDING" },
  { 0xC0020002, "RPC_NT_WRONG_KIND_OF_BINDING" },
  { 0xC0020003, "RPC_NT_INVALID_BINDING" },
  { 0xC0020004, "RPC_NT_PROTSEQ_NOT_SUPPORTED" },
  { 0xC0020005, "RPC_NT_INVALID_RPC_PROTSEQ" },
  { 0xC0020006, "RPC_NT_INVALID_STRING_UUID" },
  { 0xC0020007, "RPC_NT_INVALID_ENDPOINT_FORMAT" },
  { 0xC0020008, "RPC_NT_INVALID_NET_ADDR" },
  { 0xC0020009, "RPC_NT_NO_ENDPOINT_FOUND" },
  { 0xC002000A, "RPC_NT_INVALID_TIMEOUT" },
  { 0xC002000B, "RPC_NT_OBJECT_NOT_FOUND" },
  { 0xC002000C, "RPC_NT_ALREADY_REGISTERED" },
  { 0xC002000D, "RPC_NT_TYPE_ALREADY_REGISTERED" },
  { 0xC002000E, "RPC_NT_ALREADY_LISTENING" },
  { 0xC002000F, "RPC_NT_NO_PROTSEQS_REGISTERED" },
  { 0xC0020010, "RPC_NT_NOT_LISTENING" },
  { 0xC0020011, "RPC_NT_UNKNOWN_MGR_TYPE" },
  { 0xC0020012, "RPC_NT_UNKNOWN_IF" },
  { 0xC0020013, "RPC_NT_NO_BINDINGS" },
  { 0xC0020014, "RPC_NT_NO_PROTSEQS" },
  { 0xC0020015, "RPC_NT_CANT_CREATE_ENDPOINT" },
  { 0xC0020016, "RPC_NT_OUT_OF_RESOURCES" },
  { 0xC0020017, "RPC_NT_SERVER_UNAVAILABLE" },
  { 0xC0020018, "RPC_NT_SERVER_TOO_BUSY" },
  { 0xC0020019, "RPC_NT_INVALID_NETWORK_OPTIONS" },
  { 0xC002001A, "RPC_NT_NO_CALL_ACTIVE" },
  { 0xC002001B, "RPC_NT_CALL_FAILED" },
  { 0xC002001C, "RPC_NT_CALL_FAILED_DNE" },
  { 0xC002001D, "RPC_NT_PROTOCOL_ERROR" },
  { 0xC002001F, "RPC_NT_UNSUPPORTED_TRANS_SYN" },
  { 0xC0020021, "RPC_NT_UNSUPPORTED_TYPE" },
  { 0xC0020022, "RPC_NT_INVALID_TAG" },
  { 0xC0020023, "RPC_NT_INVALID_BOUND" },
  { 0xC0020024, "RPC_NT_NO_ENTRY_NAME" },
  { 0xC0020025, "RPC_NT_INVALID_NAME_SYNTAX" },
  { 0xC0020026, "RPC_NT_UNSUPPORTED_NAME_SYNTAX" },
  { 0xC0020028, "RPC_NT_UUID_NO_ADDRESS" },
  { 0xC0020029, "RPC_NT_DUPLICATE_ENDPOINT" },
  { 0xC002002A, "RPC_NT_UNKNOWN_AUTHN_TYPE" },
  { 0xC002002B, "RPC_NT_MAX_CALLS_TOO_SMALL" },
  { 0xC002002C, "RPC_NT_STRING_TOO_LONG" },
  { 0xC002002D, "RPC_NT_PROTSEQ_NOT_FOUND" },
  { 0xC002002E, "RPC_NT_PROCNUM_OUT_OF_RANGE" },
  { 0xC002002F, "RPC_NT_BINDING_HAS_NO_AUTH" },
  { 0xC0020030, "RPC_NT_UNKNOWN_AUTHN_SERVICE" },
  { 0xC0020031, "RPC_NT_UNKNOWN_AUTHN_LEVEL" },
  { 0xC0020032, "RPC_NT_INVALID_AUTH_IDENTITY" },
  { 0xC0020033, "RPC_NT_UNKNOWN_AUTHZ_SERVICE" },
  { 0xC0020034, "EPT_NT_INVALID_ENTRY" },
  { 0xC0020035, "EPT_NT_CANT_PERFORM_OP" },
  { 0xC0020036, "EPT_NT_NOT_REGISTERED" },
  { 0xC0020037, "RPC_NT_NOTHING_TO_EXPORT" },
  { 0xC0020038, "RPC_NT_INCOMPLETE_NAME" },
  { 0xC0020039, "RPC_NT_INVALID_VERS_OPTION" },
  { 0xC002003A, "RPC_NT_NO_MORE_MEMBERS" },
  { 0xC002003B, "RPC_NT_NOT_ALL_OBJS_UNEXPORTED" },
  { 0xC002003C, "RPC_NT_INTERFACE_NOT_FOUND" },
  { 0xC002003D, "RPC_NT_ENTRY_ALREADY_EXISTS" },
  { 0xC002003E, "RPC_NT_ENTRY_NOT_FOUND" },
  { 0xC002003F, "RPC_NT_NAME_SERVICE_UNAVAILABLE" },
  { 0xC0020040, "RPC_NT_INVALID_NAF_ID" },
  { 0xC0020041, "RPC_NT_CANNOT_SUPPORT" },
  { 0xC0020042, "RPC_NT_NO_CONTEXT_AVAILABLE" },
  { 0xC0020043, "RPC_NT_INTERNAL_ERROR" },
  { 0xC0020044, "RPC_NT_ZERO_DIVIDE" },
  { 0xC0020045, "RPC_NT_ADDRESS_ERROR" },
  { 0xC0020046, "RPC_NT_FP_DIV_ZERO" },
  { 0xC0020047, "RPC_NT_FP_UNDERFLOW" },
  { 0xC0020048, "RPC_NT_FP_OVERFLOW" },
  { 0xC0030001, "RPC_NT_NO_MORE_ENTRIES" },
  { 0xC0030002, "RPC_NT_SS_CHAR_TRANS_OPEN_FAIL" },
  { 0xC0030003, "RPC_NT_SS_CHAR_TRANS_SHORT_FILE" },
  { 0xC0030004, "RPC_NT_SS_IN_NULL_CONTEXT" },
  { 0xC0030005, "RPC_NT_SS_CONTEXT_MISMATCH" },
  { 0xC0030006, "RPC_NT_SS_CONTEXT_DAMAGED" },
  { 0xC0030007, "RPC_NT_SS_HANDLES_MISMATCH" },
  { 0xC0030008, "RPC_NT_SS_CANNOT_GET_CALL_HANDLE" },
  { 0xC0030009, "RPC_NT_NULL_REF_POINTER" },
  { 0xC003000A, "RPC_NT_ENUM_VALUE_OUT_OF_RANGE" },
  { 0xC003000B, "RPC_NT_BYTE_COUNT_TOO_SMALL" },
  { 0xC003000C, "RPC_NT_BAD_STUB_DATA" },
  { 0xC0020049, "RPC_NT_CALL_IN_PROGRESS" },
  { 0xC002004A, "RPC_NT_NO_MORE_BINDINGS" },
  { 0xC002004B, "RPC_NT_GROUP_MEMBER_NOT_FOUND" },
  { 0xC002004C, "EPT_NT_CANT_CREATE" },
  { 0xC002004D, "RPC_NT_INVALID_OBJECT" },
  { 0xC002004F, "RPC_NT_NO_INTERFACES" },
  { 0xC0020050, "RPC_NT_CALL_CANCELLED" },
  { 0xC0020051, "RPC_NT_BINDING_INCOMPLETE" },
  { 0xC0020052, "RPC_NT_COMM_FAILURE" },
  { 0xC0020053, "RPC_NT_UNSUPPORTED_AUTHN_LEVEL" },
  { 0xC0020054, "RPC_NT_NO_PRINC_NAME" },
  { 0xC0020055, "RPC_NT_NOT_RPC_ERROR" },
  { 0x40020056, "RPC_NT_UUID_LOCAL_ONLY" },
  { 0xC0020057, "RPC_NT_SEC_PKG_ERROR" },
  { 0xC0020058, "RPC_NT_NOT_CANCELLED" },
  { 0xC0030059, "RPC_NT_INVALID_ES_ACTION" },
  { 0xC003005A, "RPC_NT_WRONG_ES_VERSION" },
  { 0xC003005B, "RPC_NT_WRONG_STUB_VERSION" },
  { 0xC003005C, "RPC_NT_INVALID_PIPE_OBJECT" },
  { 0xC003005D, "RPC_NT_INVALID_PIPE_OPERATION" },
  { 0xC003005E, "RPC_NT_WRONG_PIPE_VERSION" },
  { 0x400200AF, "RPC_NT_SEND_INCOMPLETE" },
  { 0,          NULL }
};



static const true_false_string tfs_smb_flags_lock = {
	"Lock&Read, Write&Unlock are supported",
	"Lock&Read, Write&Unlock are not supported"
};
static const true_false_string tfs_smb_flags_receive_buffer = {
	"Receive buffer has been posted",
	"Receive buffer has not been posted"
};
static const true_false_string tfs_smb_flags_caseless = {
	"Path names are caseless",
	"Path names are case sensitive"
};
static const true_false_string tfs_smb_flags_canon = {
	"Pathnames are canonicalized",
	"Pathnames are not canonicalized"
};
static const true_false_string tfs_smb_flags_oplock = {
	"OpLock requested/granted",
	"OpLock not requested/granted"
};
static const true_false_string tfs_smb_flags_notify = {
	"Notify client on all modifications",
	"Notify client only on open"
};
static const true_false_string tfs_smb_flags_response = {
	"Message is a response to the client/redirector",
	"Message is a request to the server"
};

static int
dissect_smb_flags(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int offset)
{
	guint8 mask;
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	mask = tvb_get_guint8(tvb, offset);

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 1,
			"Flags: 0x%02x", mask);
		tree = proto_item_add_subtree(item, ett_smb_flags);
 	}
	proto_tree_add_boolean(tree, hf_smb_flags_response,
		tvb, offset, 1, mask);
	proto_tree_add_boolean(tree, hf_smb_flags_notify,
		tvb, offset, 1, mask);
	proto_tree_add_boolean(tree, hf_smb_flags_oplock,
		tvb, offset, 1, mask);
	proto_tree_add_boolean(tree, hf_smb_flags_canon,
		tvb, offset, 1, mask);
	proto_tree_add_boolean(tree, hf_smb_flags_caseless,
		tvb, offset, 1, mask);
	proto_tree_add_boolean(tree, hf_smb_flags_receive_buffer,
		tvb, offset, 1, mask);
	proto_tree_add_boolean(tree, hf_smb_flags_lock,
		tvb, offset, 1, mask);
	offset += 1;
	return offset;
}


 
static const true_false_string tfs_smb_flags2_long_names_allowed = {
	"Long file names are allowed in the response",
	"Long file names are not allowed in the response"
};
static const true_false_string tfs_smb_flags2_ea = {
	"Extended attributes are supported",
	"Extended attributes are not supported"
};
static const true_false_string tfs_smb_flags2_sec_sig = {
	"Security signatures are supported",
	"Security signatures are not supported"
};
static const true_false_string tfs_smb_flags2_long_names_used = {
	"Path names in request are long file names",
	"Path names in request are not long file names"
};
static const true_false_string tfs_smb_flags2_esn = {
	"Extended security negotiation is supported",
	"Extended security negotiation is not supported"
};
static const true_false_string tfs_smb_flags2_dfs = {
	"Resolve pathnames with DFS",
	"Don't resolve pathnames with DFS"
};
static const true_false_string tfs_smb_flags2_roe = {
	"Permit reads if execute-only",
	"Don't permit reads if execute-only"
};
static const true_false_string tfs_smb_flags2_nt_error = {
	"Error codes are NT error codes",
	"Error codes are DOS error codes"
};
static const true_false_string tfs_smb_flags2_string = {
	"Strings are Unicode",
	"Strings are ASCII"
};
static int
dissect_smb_flags2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int offset)
{
	guint16 mask;
	proto_item *item = NULL;
	proto_tree *tree = NULL;

	mask = tvb_get_letohs(tvb, offset);

	if(parent_tree){
		item = proto_tree_add_text(parent_tree, tvb, offset, 2,
			"Flags2: 0x%04x", mask);
		tree = proto_item_add_subtree(item, ett_smb_flags2);
	}

	proto_tree_add_boolean(tree, hf_smb_flags2_string,
		tvb, offset, 2, mask);
	proto_tree_add_boolean(tree, hf_smb_flags2_nt_error,
		tvb, offset, 2, mask);
	proto_tree_add_boolean(tree, hf_smb_flags2_roe,
		tvb, offset, 2, mask);
	proto_tree_add_boolean(tree, hf_smb_flags2_dfs,
		tvb, offset, 2, mask);
	proto_tree_add_boolean(tree, hf_smb_flags2_esn,
		tvb, offset, 2, mask);
	proto_tree_add_boolean(tree, hf_smb_flags2_long_names_used,
		tvb, offset, 2, mask);
	proto_tree_add_boolean(tree, hf_smb_flags2_sec_sig,
		tvb, offset, 2, mask);
	proto_tree_add_boolean(tree, hf_smb_flags2_ea,
		tvb, offset, 2, mask);
	proto_tree_add_boolean(tree, hf_smb_flags2_long_names_allowed,
		tvb, offset, 2, mask);
 
	offset += 2;
	return offset;
}



#define SMB_FLAGS_DIRN 0x80


static gboolean
dissect_smb(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	int offset = 0;
	proto_item *item = NULL, *hitem = NULL;
	proto_tree *tree = NULL, *htree = NULL;
	guint8          flags;
	guint16         flags2;
	smb_info_t 	si;
	smb_info_t	*sip;
	proto_item *cmd_item = NULL;
	proto_tree *cmd_tree = NULL;
	int (*dissector)(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, proto_tree *smb_tree);


	/* must check that this really is a smb packet */
	if (!tvb_bytes_exist(tvb, 0, 4))
	  return FALSE;
	if( (tvb_get_guint8(tvb, 0) != 0xff)
	 || (tvb_get_guint8(tvb, 1) != 'S')
	 || (tvb_get_guint8(tvb, 2) != 'M')
	 || (tvb_get_guint8(tvb, 3) != 'B') ){
		return FALSE;
	}
	 
	if (check_col(pinfo->fd, COL_PROTOCOL)){
		col_set_str(pinfo->fd, COL_PROTOCOL, "SMB");
	}
	if (check_col(pinfo->fd, COL_INFO)){
		col_clear(pinfo->fd, COL_INFO);
	}

	/* start off using the local variable, we will allocate a new one if we
	   need to*/
	sip = &si;
	sip->frame_req = 0;
	sip->frame_res = 0;
	sip->mid = tvb_get_letohs(tvb, offset+30);
	sip->uid = tvb_get_letohs(tvb, offset+28);
	sip->pid = tvb_get_letohs(tvb, offset+26);
	sip->tid = tvb_get_letohs(tvb, offset+24);
	flags2 = tvb_get_letohs(tvb, offset+10);
	if(flags2 & 0x8000){
		sip->unicode = TRUE; /* Mark them as Unicode */
	} else {
		sip->unicode = FALSE;
	}
	flags = tvb_get_guint8(tvb, offset+9);
	sip->request = !(flags&SMB_FLAGS_DIRN);
	sip->cmd = tvb_get_guint8(tvb, offset+4);
	sip->ddisp = 0;

	if (parent_tree) {
		item = proto_tree_add_item(parent_tree, proto_smb, tvb, offset, 
			tvb_length_remaining(tvb, 0), FALSE);
		tree = proto_item_add_subtree(item, ett_smb);

		hitem = proto_tree_add_text(tree, tvb, offset, 32, 
			"SMB Header");

		htree = proto_item_add_subtree(hitem, ett_smb_hdr);
	}

	proto_tree_add_text(htree, tvb, offset, 4, "Server Component: SMB");
	offset += 4;  /* Skip the marker */


	/* store smb_info structure so we can retreive it from the reply */
	if(sip->request){
		sip->src = &pinfo->src;
		sip->dst = &pinfo->dst;
		if(!pinfo->fd->flags.visited){
			if( (sip->mid==0)
			&&  (sip->uid==0)
			&&  (sip->pid==0)
			&&  (sip->tid==0) ){
				/* this is a broadcast SMB packet,
				   there will not be a reply.
				   We dont need to do anything */
				sip->unidir=FALSE;
			} else {
				sip->unidir=TRUE;
				sip = g_mem_chunk_alloc(smb_info_chunk);
				memcpy(sip, &si, sizeof(smb_info_t));
				sip->frame_req = pinfo->fd->num;
				sip->frame_res = 0;
				sip->src=g_malloc(sizeof(address));
				COPY_ADDRESS(sip->src, &pinfo->src);
				sip->dst=g_malloc(sizeof(address));
				COPY_ADDRESS(sip->dst, &pinfo->dst);
				g_hash_table_insert(smb_info_table, sip, sip);
			}
		}
	} else {
		sip->src = &pinfo->dst;
		sip->dst = &pinfo->src;
	}
	sip = g_hash_table_lookup(smb_info_table, sip);
	if(!sip){
		sip = &si;
	}
	/* need to redo these ones, might have changed if we got a new sip */
	sip->request = !(flags&SMB_FLAGS_DIRN);
	if(flags2 & 0x8000){
		sip->unicode = TRUE; /* Mark them as Unicode */
	} else {
		sip->unicode = FALSE;
	}

	if(sip->request){
		if(sip->frame_res){
			proto_tree_add_uint(htree, hf_smb_response_in, tvb, 0, 0, sip->frame_res);
		}
	} else {
		if(!pinfo->fd->flags.visited){
			sip->frame_res=pinfo->fd->num;
		}
		if(sip->frame_req){
			proto_tree_add_uint(htree, hf_smb_response_to, tvb, 0, 0, sip->frame_req);
		}
	}

	/* smb command */
	proto_tree_add_uint_format(htree, hf_smb_cmd, tvb, offset, 1, sip->cmd, "SMB Command: %s (0x%02x)", decode_smb_name(sip->cmd), sip->cmd);
	offset += 1;

	if(flags2 & 0x4000){
		/* handle NT 32 bit error code */
		proto_tree_add_uint(htree, hf_smb_nt_status, tvb, offset, 4,
			tvb_get_letohl(tvb, offset));
		offset += 4;
	} else {
		guint8 errclass;
		guint16 errcode;

		/* handle DOS error code & class */
		errclass = tvb_get_guint8(tvb, offset);
		proto_tree_add_uint(htree, hf_smb_error_class, tvb, offset, 1,
			errclass);
		offset += 1;

		/* reserved byte */
		proto_tree_add_item(htree, hf_smb_reserved, tvb, offset, 1, TRUE);
		offset += 1;

		/* error code */
		/* XXX - the type of this field depends on the value of
		 * "errcls", so there is isn't a single value_string array
		 * fo it, so there can't be a single field for it.
		 */
		errcode = tvb_get_letohs(tvb, offset);
		proto_tree_add_uint_format(htree, hf_smb_error_code, tvb,
			offset, 2, errcode, "Error Code: %s",
			decode_smb_error(errclass, errcode));
		offset += 2;
	}

	/* flags */
	offset = dissect_smb_flags(tvb, pinfo, htree, offset);

	/* flags2 */
	offset = dissect_smb_flags2(tvb, pinfo, htree, offset);

	/*
	 * The document at
	 *
	 *	http://www.samba.org/samba/ftp/specs/smbpub.txt
	 *
	 * (a text version of "Microsoft Networks SMB FILE SHARING
	 * PROTOCOL, Document Version 6.0p") says that:
	 *
	 *	the first 2 bytes of these 12 bytes are, for NT Create and X,
	 *	the "High Part of PID";
	 *
	 *	the next four bytes are reserved;
	 *
	 *	the next four bytes are, for SMB-over-IPX (with no
	 *	NetBIOS involved) two bytes of Session ID and two bytes
	 *	of SequenceNumber.
	 *
	 * If we ever implement SMB-over-IPX (which I suspect goes over
	 * IPX sockets 0x0550, 0x0552, and maybe 0x0554, as per the
	 * document in question), we'd probably want to have some way
	 * to determine whether this is SMB-over-IPX or not (which could
	 * be done by adding a PT_IPXSOCKET port type, having the
	 * IPX dissector set "pinfo->srcport" and "pinfo->destport",
	 * and having the SMB dissector check for a port type of
	 * PT_IPXSOCKET and for "pinfo->match_port" being either
	 * IPX_SOCKET_NWLINK_SMB_SERVER or IPX_SOCKET_NWLINK_SMB_REDIR
	 * or, if it also uses 0x0554, IPX_SOCKET_NWLINK_SMB_MESSENGER).
	 */

	/* 12 reserved bytes */
	proto_tree_add_item(htree, hf_smb_reserved, tvb, offset, 12, TRUE);
	offset += 12;

	/* TID */
	proto_tree_add_uint(htree, hf_smb_tid, tvb, offset, 2,
		sip->tid);
	offset += 2;

	/* PID */
	proto_tree_add_uint(htree, hf_smb_pid, tvb, offset, 2,
		sip->pid);
	offset += 2;

	/* UID */
	proto_tree_add_uint(htree, hf_smb_uid, tvb, offset, 2,
		sip->uid);
	offset += 2;

	/* MID */
	proto_tree_add_uint(htree, hf_smb_mid, tvb, offset, 2,
		sip->mid);
	offset += 2;

	our_tvb = tvb;
	our_pinfo = pinfo;
	if(smb_dissector[sip->cmd].request){ 
	  /* call smb command dissector */
	  pinfo->private_data = sip;
          dissect_smb_command(tvb, pinfo, parent_tree, offset, tree, sip->cmd);
	} else {
	  const u_char *pd;
	  int SMB_offset;
	  proto_item *cmd_item;
	  proto_tree *cmd_tree;

	  tvb_compat(tvb, &pd, &SMB_offset);
	  offset += SMB_offset;
	  if (check_col(pinfo->fd, COL_INFO)) {
	    col_add_fstr(pinfo->fd, COL_INFO, "%s %s",
			 decode_smb_name(sip->cmd),
			 (sip->request)? "Request" : "Response");
	  }

	  cmd_item = proto_tree_add_text(tree, NullTVB, offset,
			0, "%s %s (0x%02x)",
			decode_smb_name(sip->cmd), 
			(sip->request)?"Request":"Response",
			sip->cmd);
	  tree = proto_item_add_subtree(cmd_item, ett_smb_command);

	  (dissect[sip->cmd])(pd, offset, pinfo->fd, parent_tree, tree, si,
			      tvb_length(tvb), SMB_offset);
	}

	return TRUE;
}






	/* External routines called during the registration process */

extern void register_proto_smb_browse( void);
extern void register_proto_smb_logon( void);
extern void register_proto_smb_mailslot( void);
extern void register_proto_smb_pipe( void);
extern void register_proto_smb_mailslot( void);


void
proto_register_smb(void)
{
	static hf_register_info hf[] = {
	{ &hf_smb_cmd,
		{ "SMB Command", "smb.cmd", FT_UINT8, BASE_HEX,
		VALS(smb_cmd_vals), 0x0, "SMB Command", HFILL }},

	{ &hf_smb_word_count,
		{ "Word Count (WCT)", "smb.wct", FT_UINT8, BASE_DEC,
		NULL, 0x0, "Word Count, count of parameter words", HFILL }},

	{ &hf_smb_byte_count,
		{ "Byte Count (BCC)", "smb.bcc", FT_UINT16, BASE_DEC,
		NULL, 0x0, "Byte Count, count of data bytes", HFILL }},

	{ &hf_smb_response_to,
		{ "Response to", "smb.response_to", FT_UINT32, BASE_DEC,
		NULL, 0, "This packet is a response to the packet in this frame", HFILL }},

	{ &hf_smb_response_in,
		{ "Response in", "smb.response_in", FT_UINT32, BASE_DEC,
		NULL, 0, "The response to this packet is in this packet", HFILL }},

	{ &hf_smb_nt_status,
		{ "NT Status", "smb.nt_status", FT_UINT32, BASE_HEX,
		VALS(NT_errors), 0, "NT Status code", HFILL }},

	{ &hf_smb_error_class,
		{ "Error Class", "smb.error_class", FT_UINT8, BASE_HEX,
		VALS(errcls_types), 0, "DOS Error Class", HFILL }},

	{ &hf_smb_error_code,
		{ "Error Code", "smb.error_code", FT_UINT16, BASE_HEX,
		NULL, 0, "DOS Error Code", HFILL }},

	{ &hf_smb_reserved,
		{ "Reserved", "smb.reserved", FT_BYTES, BASE_HEX,
		NULL, 0, "Reserved bytes, must be zero", HFILL }},

	{ &hf_smb_pid,
		{ "Process ID", "smb.pid", FT_UINT16, BASE_DEC,
		NULL, 0, "Process ID", HFILL }},

	{ &hf_smb_tid,
		{ "Tree ID", "smb.tid", FT_UINT16, BASE_DEC,
		NULL, 0, "Tree ID", HFILL }},

	{ &hf_smb_uid,
		{ "User ID", "smb.uid", FT_UINT16, BASE_DEC,
		NULL, 0, "User ID", HFILL }},

	{ &hf_smb_mid,
		{ "Multiplex ID", "smb.mid", FT_UINT16, BASE_DEC,
		NULL, 0, "Multiplex ID", HFILL }},

	{ &hf_smb_flags_lock,
		{ "Lock and Read", "smb.flags.lock", FT_BOOLEAN, 8,
		TFS(&tfs_smb_flags_lock), 0x01, "Are Lock&Read and Write&Unlock operations supported?", HFILL }},

	{ &hf_smb_flags_receive_buffer,
		{ "Receive Buffer Posted", "smb.flags.receive_buffer", FT_BOOLEAN, 8,
		TFS(&tfs_smb_flags_receive_buffer), 0x02, "Have receive buffers been reported?", HFILL }},

	{ &hf_smb_flags_caseless,
		{ "Case Sensitivity", "smb.flags.caseless", FT_BOOLEAN, 8,
		TFS(&tfs_smb_flags_caseless), 0x08, "Are pathnames caseless or casesensitive?", HFILL }},

	{ &hf_smb_flags_canon,
		{ "Canonicalized Pathnames", "smb.flags.canon", FT_BOOLEAN, 8,
		TFS(&tfs_smb_flags_canon), 0x10, "Are pathnames canonicalized?", HFILL }},

	{ &hf_smb_flags_oplock,
		{ "Oplocks", "smb.flags.oplock", FT_BOOLEAN, 8,
		TFS(&tfs_smb_flags_oplock), 0x20, "Is an oplock requested/granted?", HFILL }},

	{ &hf_smb_flags_notify,
		{ "Notify", "smb.flags.notify", FT_BOOLEAN, 8,
		TFS(&tfs_smb_flags_notify), 0x40, "Notify on open or all?", HFILL }},

	{ &hf_smb_flags_response,
		{ "Request/Response", "smb.flags.response", FT_BOOLEAN, 8,
		TFS(&tfs_smb_flags_response), 0x80, "Is this a request or a response?", HFILL }},

	{ &hf_smb_flags2_long_names_allowed,
		{ "Long Names Allowed", "smb.flags2.long_names_allowed", FT_BOOLEAN, 16,
		TFS(&tfs_smb_flags2_long_names_allowed), 0x0001, "Are long file names allowed in the response?", HFILL }},

	{ &hf_smb_flags2_ea,
		{ "Extended Attributes", "smb.flags2.ea", FT_BOOLEAN, 16,
		TFS(&tfs_smb_flags2_ea), 0x0002, "Are extended attributes supported?", HFILL }},

	{ &hf_smb_flags2_sec_sig,
		{ "Security Signatures", "smb.flags2.sec_sig", FT_BOOLEAN, 16,
		TFS(&tfs_smb_flags2_sec_sig), 0x0004, "Are security signatures supported?", HFILL }},

	{ &hf_smb_flags2_long_names_used,
		{ "Long Names Used", "smb.flags2.long_names_used", FT_BOOLEAN, 16,
		TFS(&tfs_smb_flags2_long_names_used), 0x0040, "Are pathnames in this request long file names?", HFILL }},

	{ &hf_smb_flags2_esn,
		{ "Extended Security Negotiation", "smb.flags2.esn", FT_BOOLEAN, 16,
		TFS(&tfs_smb_flags2_esn), 0x0800, "Is extended security negotiation supported?", HFILL }},

	{ &hf_smb_flags2_dfs,
		{ "Dfs", "smb.flags2.dfs", FT_BOOLEAN, 16,
		TFS(&tfs_smb_flags2_dfs), 0x1000, "Can pathnames be resolved using Dfs?", HFILL }},

	{ &hf_smb_flags2_roe,
		{ "Execute-only Reads", "smb.flags2.roe", FT_BOOLEAN, 16,
		TFS(&tfs_smb_flags2_roe), 0x2000, "Will reads be allowed for execute-only files?", HFILL }},

	{ &hf_smb_flags2_nt_error,
		{ "Error Code Type", "smb.flags2.nt_error", FT_BOOLEAN, 16,
		TFS(&tfs_smb_flags2_nt_error), 0x4000, "Are error codes NT or DOS format?", HFILL }},

	{ &hf_smb_flags2_string,
		{ "Unicode Strings", "smb.flags2.string", FT_BOOLEAN, 16,
		TFS(&tfs_smb_flags2_string), 0x8000, "Are strings ASCII or Unicode?", HFILL }},

	{ &hf_smb_buffer_format,
		{ "Buffer Format", "smb.buffer_format", FT_UINT8, BASE_DEC,
		VALS(buffer_format_vals), 0x0, "Buffer Format, type of buffer", HFILL }},

	{ &hf_smb_dialect_name,
		{ "Name", "smb.dialect.name", FT_STRING, BASE_NONE,
		NULL, 0, "Name of dialect", HFILL }},

	{ &hf_smb_dialect_index,
		{ "Selected Index", "smb.dialect.index", FT_UINT16, BASE_DEC,
		NULL, 0, "Index of selected dialect", HFILL }},

	{ &hf_smb_max_trans_buf_size,
		{ "Max Buffer Size", "smb.max_bufsize", FT_UINT32, BASE_DEC,
		NULL, 0, "Maximum transmit buffer size", HFILL }},

	{ &hf_smb_max_mpx_count,
		{ "Max Mpx Count", "smb.max_mpx_count", FT_UINT16, BASE_DEC,
		NULL, 0, "Maximum pending multiplexed requests", HFILL }},

	{ &hf_smb_max_vcs_num,
		{ "Max VCs", "smb.max_vcs", FT_UINT16, BASE_DEC,
		NULL, 0, "Maximum VCs between client and server", HFILL }},

	{ &hf_smb_session_key,
		{ "Session Key", "smb.session_key", FT_UINT32, BASE_HEX,
		NULL, 0, "Unique token identifying this session", HFILL }},

	{ &hf_smb_server_timezone,
		{ "Time Zone", "smb.server.timezone", FT_INT16, BASE_DEC,
		NULL, 0, "Current timezone at server.", HFILL }},

	{ &hf_smb_encryption_key_length,
		{ "Key Length", "smb.encryption_key_length", FT_UINT16, BASE_DEC,
		NULL, 0, "Encryption key length (must be 0 if not LM2.1 dialect)", HFILL }},

	{ &hf_smb_encryption_key,
		{ "Encryption Key", "smb.encryption_key", FT_BYTES, BASE_HEX,
		NULL, 0, "Challenge/Response Encryption Key (for LM2.1 dialect)", HFILL }},

	{ &hf_smb_primary_domain,
		{ "Primary Domain", "smb.primary_domain", FT_STRING, BASE_NONE,
		NULL, 0, "The server's primary domain", HFILL }},

	{ &hf_smb_max_raw_buf_size,
		{ "Max Raw Buffer", "smb.max_raw", FT_UINT32, BASE_DEC,
		NULL, 0, "Maximum raw buffer size", HFILL }},

	{ &hf_smb_server_guid,
		{ "Server GUID", "smb.server.guid", FT_BYTES, BASE_HEX,
		NULL, 0, "Globally unique identifier for this server", HFILL }},

	{ &hf_smb_security_blob,
		{ "Security Blob", "smb.security.blob", FT_BYTES, BASE_HEX,
		NULL, 0, "Security blob", HFILL }},

	{ &hf_smb_sm_mode16,
		{ "Mode", "smb.sm.mode", FT_BOOLEAN, 16,
		TFS(&tfs_sm_mode), SECURITY_MODE_MODE, "User or Share security mode?", HFILL }},

	{ &hf_smb_sm_password16,
		{ "Password", "smb.sm.password", FT_BOOLEAN, 16,
		TFS(&tfs_sm_password), SECURITY_MODE_PASSWORD, "Encrypted or plaintext passwords?", HFILL }},

	{ &hf_smb_sm_mode,
		{ "Mode", "smb.sm.mode", FT_BOOLEAN, 8,
		TFS(&tfs_sm_mode), SECURITY_MODE_MODE, "User or Share security mode?", HFILL }},

	{ &hf_smb_sm_password,
		{ "Password", "smb.sm.password", FT_BOOLEAN, 8,
		TFS(&tfs_sm_password), SECURITY_MODE_PASSWORD, "Encrypted or plaintext passwords?", HFILL }},

	{ &hf_smb_sm_signatures,
		{ "Signatures", "smb.sm.signatures", FT_BOOLEAN, 8,
		TFS(&tfs_sm_signatures), SECURITY_MODE_SIGNATURES, "Are security signatures enabled?", HFILL }},

	{ &hf_smb_sm_sig_required,
		{ "Sig Req", "smb.sm.sig_required", FT_BOOLEAN, 8,
		TFS(&tfs_sm_sig_required), SECURITY_MODE_SIG_REQUIRED, "Are security signatures required?", HFILL }},

	{ &hf_smb_rm_read,
		{ "Read Raw", "smb.rm.read", FT_BOOLEAN, 16,
		TFS(&tfs_rm_read), RAWMODE_READ, "Is Read Raw supported?", HFILL }},

	{ &hf_smb_rm_write,
		{ "Write Raw", "smb.rm.write", FT_BOOLEAN, 16,
		TFS(&tfs_rm_write), RAWMODE_WRITE, "Is Write Raw supported?", HFILL }},

	{ &hf_smb_server_date_time,
		{ "Server Date and Time", "smb.server_date_time", FT_ABSOLUTE_TIME, BASE_NONE,
		NULL, 0, "Current date and time at server", HFILL }},

	{ &hf_smb_server_smb_date,
		{ "Server Date", "smb.server_date_time.smb_date", FT_UINT16, BASE_HEX,
		NULL, 0, "Current date at server, SMB_DATE format", HFILL }},

	{ &hf_smb_server_smb_time,
		{ "Server Time", "smb.server_date_time.smb_time", FT_UINT16, BASE_HEX,
		NULL, 0, "Current time at server, SMB_TIME format", HFILL }},

	{ &hf_smb_server_cap_raw_mode,
		{ "Raw Mode", "smb.server.cap.raw_mode", FT_BOOLEAN, 32,
		TFS(&tfs_server_cap_raw_mode), SERVER_CAP_RAW_MODE, "Are Raw Read and Raw Write supported?", HFILL }},

	{ &hf_smb_server_cap_mpx_mode,
		{ "MPX Mode", "smb.server.cap.mpx_mode", FT_BOOLEAN, 32,
		TFS(&tfs_server_cap_mpx_mode), SERVER_CAP_MPX_MODE, "Are Read Mpx and Write Mpx supported?", HFILL }},

	{ &hf_smb_server_cap_unicode,
		{ "Unicode", "smb.server.cap.unicode", FT_BOOLEAN, 32,
		TFS(&tfs_server_cap_unicode), SERVER_CAP_UNICODE, "Are Unicode strings supported?", HFILL }},

	{ &hf_smb_server_cap_large_files,
		{ "Large Files", "smb.server.cap.large_files", FT_BOOLEAN, 32,
		TFS(&tfs_server_cap_large_files), SERVER_CAP_LARGE_FILES, "Are large files (>4GB) supported?", HFILL }},

	{ &hf_smb_server_cap_nt_smbs,
		{ "NT SMBs", "smb.server.cap.nt_smbs", FT_BOOLEAN, 32,
		TFS(&tfs_server_cap_nt_smbs), SERVER_CAP_NT_SMBS, "Are NT SMBs supported?", HFILL }},

	{ &hf_smb_server_cap_rpc_remote_apis,
		{ "RPC Remote APIs", "smb.server.cap.rpc_remote_apis", FT_BOOLEAN, 32,
		TFS(&tfs_server_cap_rpc_remote_apis), SERVER_CAP_RPC_REMOTE_APIS, "Are RPC Remote APIs supported?", HFILL }},

	{ &hf_smb_server_cap_nt_status,
		{ "NT Status Codes", "smb.server.cap.nt_status", FT_BOOLEAN, 32,
		TFS(&tfs_server_cap_nt_status), SERVER_CAP_STATUS32, "Are NT Status Codes supported?", HFILL }},

	{ &hf_smb_server_cap_level_ii_oplocks,
		{ "Level 2 Oplocks", "smb.server.cap.level_2_oplocks", FT_BOOLEAN, 32,
		TFS(&tfs_server_cap_level_ii_oplocks), SERVER_CAP_LEVEL_II_OPLOCKS, "Are Level 2 oplocks supported?", HFILL }},

	{ &hf_smb_server_cap_lock_and_read,
		{ "Lock and Read", "smb.server.cap.lock_and_read", FT_BOOLEAN, 32,
		TFS(&tfs_server_cap_lock_and_read), SERVER_CAP_LOCK_AND_READ, "Is Lock and Read supported?", HFILL }},

	{ &hf_smb_server_cap_nt_find,
		{ "NT Find", "smb.server.cap.nt_find", FT_BOOLEAN, 32,
		TFS(&tfs_server_cap_nt_find), SERVER_CAP_NT_FIND, "Is NT Find supported?", HFILL }},

	{ &hf_smb_server_cap_dfs,
		{ "Dfs", "smb.server.cap.dfs", FT_BOOLEAN, 32,
		TFS(&tfs_server_cap_dfs), SERVER_CAP_DFS, "Is Dfs supported?", HFILL }},

	{ &hf_smb_server_cap_infolevel_passthru,
		{ "Infolevel Passthru", "smb.server.cap.infolevel_passthru", FT_BOOLEAN, 32,
		TFS(&tfs_server_cap_infolevel_passthru), SERVER_CAP_INFOLEVEL_PASSTHRU, "Is NT information level request passthrough supported?", HFILL }},

	{ &hf_smb_server_cap_large_readx,
		{ "Large ReadX", "smb.server.cap.large_readx", FT_BOOLEAN, 32,
		TFS(&tfs_server_cap_large_readx), SERVER_CAP_LARGE_READX, "Is Large Read andX supported?", HFILL }},

	{ &hf_smb_server_cap_large_writex,
		{ "Large WriteX", "smb.server.cap.large_writex", FT_BOOLEAN, 32,
		TFS(&tfs_server_cap_large_writex), SERVER_CAP_LARGE_WRITEX, "Is Large Write andX supported?", HFILL }},

	{ &hf_smb_server_cap_unix,
		{ "UNIX", "smb.server.cap.unix", FT_BOOLEAN, 32,
		TFS(&tfs_server_cap_unix), SERVER_CAP_UNIX , "Are UNIX extensions supported?", HFILL }},

	{ &hf_smb_server_cap_reserved,
		{ "Reserved", "smb.server.cap.reserved", FT_BOOLEAN, 32,
		TFS(&tfs_server_cap_reserved), SERVER_CAP_RESERVED, "RESERVED", HFILL }},

	{ &hf_smb_server_cap_bulk_transfer,
		{ "Bulk Transfer", "smb.server.cap.bulk_transfer", FT_BOOLEAN, 32,
		TFS(&tfs_server_cap_bulk_transfer), SERVER_CAP_BULK_TRANSFER, "Are Bulk Read and Bulk Write supported?", HFILL }},

	{ &hf_smb_server_cap_compressed_data,
		{ "Compressed Data", "smb.server.cap.compressed_data", FT_BOOLEAN, 32,
		TFS(&tfs_server_cap_compressed_data), SERVER_CAP_COMPRESSED_DATA, "Is compressed data transfer supported?", HFILL }},

	{ &hf_smb_server_cap_extended_security,
		{ "Extended Security", "smb.server.cap.extended_security", FT_BOOLEAN, 32,
		TFS(&tfs_server_cap_extended_security), SERVER_CAP_EXTENDED_SECURITY, "Are Extended security exchanges supported?", HFILL }},

	{ &hf_smb_system_time,
		{ "System Time", "smb.system.time", FT_ABSOLUTE_TIME, BASE_NONE,
		NULL, 0, "System Time", HFILL }},

	{ &hf_smb_unknown,
		{ "Unknown Data", "smb.unknown", FT_BYTES, BASE_HEX,
		NULL, 0, "Unknown Data. Should be implemented by someone", HFILL }},

	{ &hf_smb_dir_name,
		{ "Directory", "smb.dir_name", FT_STRING, BASE_NONE,
		NULL, 0, "SMB Directory Name", HFILL }},

	{ &hf_smb_echo_count,
		{ "Echo Count", "smb.echo.count", FT_UINT16, BASE_DEC,
		NULL, 0, "Number of times to echo data back", HFILL }},

	{ &hf_smb_echo_data,
		{ "Echo Data", "smb.echo.data", FT_BYTES, BASE_HEX,
		NULL, 0, "Data for SMB Echo Request/Response", HFILL }},

	{ &hf_smb_echo_seq_num,
		{ "Echo Seq Num", "smb.echo.seq_num", FT_UINT16, BASE_DEC,
		NULL, 0, "Sequence number for this echo response", HFILL }},

	{ &hf_smb_max_buf_size,
		{ "Max Buffer", "smb.max_buf", FT_UINT16, BASE_DEC,
		NULL, 0, "Max client buffer size", HFILL }},

	{ &hf_smb_path,
		{ "Path", "smb.path", FT_STRING, BASE_NONE,
		NULL, 0, "Path. Server name and share name", HFILL }},

	{ &hf_smb_service,
		{ "Service", "smb.service", FT_STRING, BASE_NONE,
		NULL, 0, "Service name", HFILL }},

	{ &hf_smb_password,
		{ "Password", "smb.password", FT_BYTES, BASE_NONE,
		NULL, 0, "Password", HFILL }},

	{ &hf_smb_move_flags_file,
		{ "Must be file", "smb.move.flags.file", FT_BOOLEAN, 16,
		TFS(&tfs_mf_file), 0x0001, "Must target be a file?", HFILL }},

	{ &hf_smb_move_flags_dir,
		{ "Must be directory", "smb.move.flags.dir", FT_BOOLEAN, 16,
		TFS(&tfs_mf_dir), 0x0002, "Must target be a directory?", HFILL }},

	{ &hf_smb_move_flags_verify,
		{ "Verify writes", "smb.move.flags.verify", FT_BOOLEAN, 16,
		TFS(&tfs_mf_verify), 0x0010, "Verify all writes?", HFILL }},

	{ &hf_smb_count,
		{ "Count", "smb.count", FT_UINT32, BASE_DEC,
		NULL, 0, "Count number of items/bytes", HFILL }},

	{ &hf_smb_file_name,
		{ "File Name", "smb.file", FT_STRING, BASE_NONE,
		NULL, 0, "File Name", HFILL }},

	{ &hf_smb_open_function_create,
		{ "Create", "smb.open.function.create", FT_BOOLEAN, 16,
		TFS(&tfs_of_create), 0x0010, "Create file if it doesn't exist?", HFILL }},

	{ &hf_smb_open_function_open,
		{ "Open", "smb.open.function.open", FT_UINT16, BASE_HEX,
		VALS(of_open), 0x0003, "Action to be taken on open if file exists", HFILL }},

	{ &hf_smb_fid,
		{ "FID", "smb.fid", FT_UINT16, BASE_HEX,
		NULL, 0, "FID: FileID", HFILL }},

	{ &hf_smb_file_attr_read_only,
		{ "Read Only", "smb.file.attribute.read_only", FT_BOOLEAN, 16,
		TFS(&tfs_file_attribute_read_only), FILE_ATTRIBUTE_READ_ONLY, "READ ONLY file attribute", HFILL }},

	{ &hf_smb_file_attr_hidden,
		{ "Hidden", "smb.file.attribute.hidden", FT_BOOLEAN, 16,
		TFS(&tfs_file_attribute_hidden), FILE_ATTRIBUTE_HIDDEN, "HIDDEN file attribute", HFILL }},

	{ &hf_smb_file_attr_system,
		{ "System", "smb.file.attribute.system", FT_BOOLEAN, 16,
		TFS(&tfs_file_attribute_system), FILE_ATTRIBUTE_SYSTEM, "SYSTEM file attribute", HFILL }},

	{ &hf_smb_file_attr_volume,
		{ "Volume ID", "smb.file.attribute.volume", FT_BOOLEAN, 16,
		TFS(&tfs_file_attribute_volume), FILE_ATTRIBUTE_VOLUME, "VOLUME file attribute", HFILL }},

	{ &hf_smb_file_attr_directory,
		{ "Directory", "smb.file.attribute.directory", FT_BOOLEAN, 16,
		TFS(&tfs_file_attribute_directory), FILE_ATTRIBUTE_DIRECTORY, "DIRECTORY file attribute", HFILL }},

	{ &hf_smb_file_attr_archive,
		{ "Archive", "smb.file.attribute.archive", FT_BOOLEAN, 16,
		TFS(&tfs_file_attribute_archive), FILE_ATTRIBUTE_ARCHIVE, "ARCHIVE file attribute", HFILL }},

	{ &hf_smb_file_attr_device,
		{ "Device", "smb.file.attribute.device", FT_BOOLEAN, 16,
		TFS(&tfs_file_attribute_device), FILE_ATTRIBUTE_DEVICE, "Is this file a device?", HFILL }},

	{ &hf_smb_file_attr_normal,
		{ "Normal", "smb.file.attribute.normal", FT_BOOLEAN, 16,
		TFS(&tfs_file_attribute_normal), FILE_ATTRIBUTE_NORMAL, "Is this a normal file?", HFILL }},

	{ &hf_smb_file_attr_temporary,
		{ "Temporary", "smb.file.attribute.temporary", FT_BOOLEAN, 16,
		TFS(&tfs_file_attribute_temporary), FILE_ATTRIBUTE_TEMPORARY, "Is this a temporary file?", HFILL }},

	{ &hf_smb_file_attr_sparse,
		{ "Sparse", "smb.file.attribute.sparse", FT_BOOLEAN, 16,
		TFS(&tfs_file_attribute_sparse), FILE_ATTRIBUTE_SPARSE, "Is this a sparse file?", HFILL }},

	{ &hf_smb_file_attr_reparse,
		{ "Reparse Point", "smb.file.attribute.reparse", FT_BOOLEAN, 16,
		TFS(&tfs_file_attribute_reparse), FILE_ATTRIBUTE_REPARSE, "Does this file have an associated reparse point?", HFILL }},

	{ &hf_smb_file_attr_compressed,
		{ "Compressed", "smb.file.attribute.compressed", FT_BOOLEAN, 16,
		TFS(&tfs_file_attribute_compressed), FILE_ATTRIBUTE_COMPRESSED, "Is this file compressed?", HFILL }},

	{ &hf_smb_file_attr_offline,
		{ "Offline", "smb.file.attribute.offline", FT_BOOLEAN, 16,
		TFS(&tfs_file_attribute_offline), FILE_ATTRIBUTE_OFFLINE, "Is this file offline?", HFILL }},

	{ &hf_smb_file_attr_not_content_indexed,
		{ "Content Indexed", "smb.file.attribute.not_content_indexed", FT_BOOLEAN, 16,
		TFS(&tfs_file_attribute_not_content_indexed), FILE_ATTRIBUTE_NOT_CONTENT_INDEXED, "May this file be indexed by the content indexing service", HFILL }},

	{ &hf_smb_file_attr_encrypted,
		{ "Encrypted", "smb.file.attribute.encrypted", FT_BOOLEAN, 16,
		TFS(&tfs_file_attribute_encrypted), FILE_ATTRIBUTE_ENCRYPTED, "Is this file encrypted?", HFILL }},

	{ &hf_smb_file_size,
		{ "File Size", "smb.file.size", FT_UINT32, BASE_DEC,
		NULL, 0, "File Size", HFILL }},

	{ &hf_smb_last_write_time,
		{ "Last Write Time", "smb.last_write.time", FT_ABSOLUTE_TIME, BASE_HEX,
		NULL, 0, "Last time this file was written to", HFILL }},

	{ &hf_smb_search_attribute_read_only,
		{ "Read Only", "smb.search.attribute.read_only", FT_BOOLEAN, 16,
		TFS(&tfs_file_attribute_read_only), FILE_ATTRIBUTE_READ_ONLY, "READ ONLY search attribute", HFILL }},

	{ &hf_smb_search_attribute_hidden,
		{ "Hidden", "smb.search.attribute.hidden", FT_BOOLEAN, 16,
		TFS(&tfs_file_attribute_hidden), FILE_ATTRIBUTE_HIDDEN, "HIDDEN search attribute", HFILL }},

	{ &hf_smb_search_attribute_system,
		{ "System", "smb.search.attribute.system", FT_BOOLEAN, 16,
		TFS(&tfs_file_attribute_system), FILE_ATTRIBUTE_SYSTEM, "SYSTEM search attribute", HFILL }},

	{ &hf_smb_search_attribute_volume,
		{ "Volume ID", "smb.search.attribute.volume", FT_BOOLEAN, 16,
		TFS(&tfs_file_attribute_volume), FILE_ATTRIBUTE_VOLUME, "VOLUME search attribute", HFILL }},

	{ &hf_smb_search_attribute_directory,
		{ "Directory", "smb.search.attribute.directory", FT_BOOLEAN, 16,
		TFS(&tfs_file_attribute_directory), FILE_ATTRIBUTE_DIRECTORY, "DIRECTORY search attribute", HFILL }},

	{ &hf_smb_search_attribute_archive,
		{ "Archive", "smb.search.attribute.archive", FT_BOOLEAN, 16,
		TFS(&tfs_file_attribute_archive), FILE_ATTRIBUTE_ARCHIVE, "ARCHIVE search attribute", HFILL }},

	{ &hf_smb_access_mode,
		{ "Access Mode", "smb.access.mode", FT_UINT16, BASE_HEX,
		VALS(da_access_vals), 0x0007, "Access Mode", HFILL }},

	{ &hf_smb_access_sharing,
		{ "Sharing Mode", "smb.access.sharing", FT_UINT16, BASE_HEX,
		VALS(da_sharing_vals), 0x0070, "Sharing Mode", HFILL }},

	{ &hf_smb_access_locality,
		{ "Locality", "smb.access.locality", FT_UINT16, BASE_HEX,
		VALS(da_locality_vals), 0x0700, "Locality of reference", HFILL }},

	{ &hf_smb_access_caching,
		{ "Caching", "smb.access.caching", FT_BOOLEAN, 16,
		TFS(&tfs_da_caching), 0x1000, "Caching mode?", HFILL }},

	{ &hf_smb_access_writetru,
		{ "Writethrough", "smb.access.writethrough", FT_BOOLEAN, 16,
		TFS(&tfs_da_writetru), 0x4000, "Writethrough mode?", HFILL }},

	{ &hf_smb_create_time,
		{ "Created", "smb.create.time", FT_ABSOLUTE_TIME, BASE_NONE,
		NULL, 0, "Creation Time", HFILL }},

	{ &hf_smb_create_dos_date,
		{ "Create Date", "smb.create.smb.date", FT_UINT16, BASE_HEX,
		NULL, 0, "Create Date, SMB_DATE format", HFILL }},

	{ &hf_smb_create_dos_time,
		{ "Create Time", "smb.create.smb.time", FT_UINT16, BASE_HEX,
		NULL, 0, "Create Time, SMB_TIME format", HFILL }},

	{ &hf_smb_last_write_date,
		{ "Last Write", "smb.last_write.date", FT_ABSOLUTE_TIME, BASE_NONE,
		NULL, 0, "Last Write", HFILL }},

	{ &hf_smb_last_write_dos_date,
		{ "Last Write Date", "smb.last_write.smb.date", FT_UINT16, BASE_HEX,
		NULL, 0, "Last Write Date, SMB_DATE format", HFILL }},

	{ &hf_smb_last_write_dos_time,
		{ "Last Write Time", "smb.last_write.smb.time", FT_UINT16, BASE_HEX,
		NULL, 0, "Last Write Time, SMB_TIME format", HFILL }},

	{ &hf_smb_old_file_name,
		{ "Old File Name", "smb.file", FT_STRING, BASE_NONE,
		NULL, 0, "Old File Name (When renaming a file)", HFILL }},

	{ &hf_smb_offset,
		{ "Offset", "smb.offset", FT_UINT32, BASE_DEC,
		NULL, 0, "Offset in file", HFILL }},

	{ &hf_smb_remaining,
		{ "Remaining", "smb.remaining", FT_UINT32, BASE_DEC,
		NULL, 0, "Remaining number of bytes", HFILL }},

	{ &hf_smb_padding,
		{ "Padding", "smb.padding", FT_BYTES, BASE_HEX,
		NULL, 0, "Padding or unknown data", HFILL }},

	{ &hf_smb_file_data,
		{ "File Data", "smb.file.data", FT_BYTES, BASE_HEX,
		NULL, 0, "Data read/written to the file", HFILL }},

	{ &hf_smb_data_len,
		{ "Data Length", "smb.data_len", FT_UINT16, BASE_DEC,
		NULL, 0, "Length of data", HFILL }},

	{ &hf_smb_seek_mode,
		{ "Seek Mode", "smb.seek_mode", FT_UINT16, BASE_DEC,
		VALS(seek_mode_vals), 0, "Seek Mode, what type of seek", HFILL }},

	{ &hf_smb_access_time,
		{ "Last Access", "smb.access.time", FT_ABSOLUTE_TIME, BASE_NONE,
		NULL, 0, "Last Access Time", HFILL }},

	{ &hf_smb_access_dos_date,
		{ "Last Access Date", "smb.access.smb.date", FT_UINT16, BASE_HEX,
		NULL, 0, "Last Access Date, SMB_DATE format", HFILL }},

	{ &hf_smb_access_dos_time,
		{ "Last Access Time", "smb.access.smb.time", FT_UINT16, BASE_HEX,
		NULL, 0, "Last Access Time, SMB_TIME format", HFILL }},

	{ &hf_smb_data_size,
		{ "Data Size", "smb.data_size", FT_UINT32, BASE_DEC,
		NULL, 0, "Data Size", HFILL }},

	{ &hf_smb_alloc_size,
		{ "Allocation Size", "smb.alloc_size", FT_UINT32, BASE_DEC,
		NULL, 0, "Number of bytes to reserve on create or truncate", HFILL }},

	{ &hf_smb_max_count,
		{ "Max Count", "smb.maxcount", FT_UINT16, BASE_DEC,
		NULL, 0, "Maximum Count", HFILL }},

	{ &hf_smb_min_count,
		{ "Min Count", "smb.mincount", FT_UINT16, BASE_DEC,
		NULL, 0, "Minimum Count", HFILL }},

	{ &hf_smb_timeout,
		{ "Timeout", "smb.timeout", FT_UINT32, BASE_DEC,
		NULL, 0, "Timeout in miliseconds", HFILL }},

	{ &hf_smb_high_offset,
		{ "High Offset", "smb.offset_high", FT_UINT32, BASE_DEC,
		NULL, 0, "High 32 Bits Of File Offset", HFILL }},

	{ &hf_smb_units,
		{ "Total Units", "smb.units", FT_UINT16, BASE_DEC,
		NULL, 0, "Total number of units at server", HFILL }},

	{ &hf_smb_bpu,
		{ "Blocks Per Unit", "smb.bpu", FT_UINT16, BASE_DEC,
		NULL, 0, "Blocks per unit at server", HFILL }},

	{ &hf_smb_blocksize,
                { "Block Size", "smb.blocksize", FT_UINT16, BASE_DEC,
		NULL, 0, "Block size (in bytes) at server", HFILL }},

	{ &hf_smb_freeunits,
		{ "Free Units", "smb.free_units", FT_UINT16, BASE_DEC,
		NULL, 0, "Number of free units at server", HFILL }},


	};
	static gint *ett[] = {
		&ett_smb,
		&ett_smb_hdr,
		&ett_smb_command,
		&ett_smb_fileattributes,
		&ett_smb_capabilities,
		&ett_smb_aflags,
		&ett_smb_dialect,
		&ett_smb_dialects,
		&ett_smb_mode,
		&ett_smb_rawmode,
		&ett_smb_flags,
		&ett_smb_flags2,
		&ett_smb_desiredaccess,
		&ett_smb_search,
		&ett_smb_file,
		&ett_smb_openfunction,
		&ett_smb_filetype,
		&ett_smb_openaction,
		&ett_smb_writemode,
		&ett_smb_lock_type,
		&ett_smb_ssetupandxaction,
		&ett_smb_optionsup,
		&ett_smb_time_date,
		&ett_smb_64bit_time,
		&ett_smb_move_flags,
		&ett_smb_file_attributes,
	};

	proto_smb = proto_register_protocol("SMB (Server Message Block Protocol)",
	    "SMB", "smb");

	proto_register_subtree_array(ett, array_length(ett));
	proto_register_field_array(proto_smb, hf, array_length(hf));
	register_init_routine(&smb_init_protocol);
	register_init_routine(&smb_info_init);

	register_proto_smb_browse();
	register_proto_smb_logon();
	register_proto_smb_mailslot();
	register_proto_smb_pipe();
}

void
proto_reg_handoff_smb(void)
{
	heur_dissector_add("netbios", dissect_smb, proto_smb);
}
