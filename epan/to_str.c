/* to_str.c
 * Routines for utilities to convert various other types to strings.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <glib.h>

#include "wmem/wmem.h"
#include "proto.h"
#include "to_str.h"
#include "to_str-int.h"
#include "strutil.h"
#include <wsutil/pint.h>

/*
 * If a user _does_ pass in a too-small buffer, this is probably
 * going to be too long to fit.  However, even a partial string
 * starting with "[Buf" should provide enough of a clue to be
 * useful.
 */
#define BUF_TOO_SMALL_ERR "[Buffer too small]"

static inline char
low_nibble_of_octet_to_hex(guint8 oct)
{
	/* At least one version of Apple's C compiler/linker is buggy, causing
	   a complaint from the linker about the "literal C string section"
	   not ending with '\0' if we initialize a 16-element "char" array with
	   a 16-character string, the fact that initializing such an array with
	   such a string is perfectly legitimate ANSI C nonwithstanding, the 17th
	   '\0' byte in the string nonwithstanding. */
	static const gchar hex_digits[16] =
	{ '0', '1', '2', '3', '4', '5', '6', '7',
	  '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

	return hex_digits[oct & 0xF];
}

static inline char *
byte_to_hex(char *out, guint32 dword)
{
	*out++ = low_nibble_of_octet_to_hex(dword >> 4);
	*out++ = low_nibble_of_octet_to_hex(dword);
	return out;
}

char *
word_to_hex(char *out, guint16 word)
{
	out = byte_to_hex(out, word >> 8);
	out = byte_to_hex(out, word);
	return out;
}

char *
word_to_hex_punct(char *out, guint16 word, char punct)
{
	out = byte_to_hex(out, word >> 8);
	*out++ = punct;
	out = byte_to_hex(out, word);
	return out;
}

char *
word_to_hex_npad(char *out, guint16 word)
{
	if (word >= 0x1000)
		*out++ = low_nibble_of_octet_to_hex((guint8)(word >> 12));
	if (word >= 0x0100)
		*out++ = low_nibble_of_octet_to_hex((guint8)(word >> 8));
	if (word >= 0x0010)
		*out++ = low_nibble_of_octet_to_hex((guint8)(word >> 4));
	*out++ = low_nibble_of_octet_to_hex((guint8)(word >> 0));
	return out;
}

char *
dword_to_hex(char *out, guint32 dword)
{
	out = word_to_hex(out, dword >> 16);
	out = word_to_hex(out, dword);
	return out;
}

char *
dword_to_hex_punct(char *out, guint32 dword, char punct)
{
	out = word_to_hex_punct(out, dword >> 16, punct);
	*out++ = punct;
	out = word_to_hex_punct(out, dword, punct);
	return out;
}

char *
qword_to_hex(char *out, guint64 qword)
{
	out = dword_to_hex(out, (guint32)(qword >> 32));
	out = dword_to_hex(out, (guint32)(qword & 0xffffffff));
	return out;
}

char *
qword_to_hex_punct(char *out, guint64 qword, char punct)
{
	out = dword_to_hex_punct(out, (guint32)(qword >> 32), punct);
	*out++ = punct;
	out = dword_to_hex_punct(out, (guint32)(qword & 0xffffffff), punct);
	return out;
}

/*
 * This does *not* null-terminate the string.  It returns a pointer
 * to the position in the string following the last character it
 * puts there, so that the caller can either put the null terminator
 * in or can append more stuff to the buffer.
 *
 * There needs to be at least len * 2 bytes left in the buffer.
 */
char *
bytes_to_hexstr(char *out, const guint8 *ad, guint32 len)
{
	guint32 i;

	if (!ad)
		REPORT_DISSECTOR_BUG("Null pointer passed to bytes_to_hexstr()");

	for (i = 0; i < len; i++)
		out = byte_to_hex(out, ad[i]);
	return out;
}

/*
 * This does *not* null-terminate the string.  It returns a pointer
 * to the position in the string following the last character it
 * puts there, so that the caller can either put the null terminator
 * in or can append more stuff to the buffer.
 *
 * There needs to be at least len * 3 - 1 bytes left in the buffer.
 */
char *
bytes_to_hexstr_punct(char *out, const guint8 *ad, guint32 len, char punct)
{
	guint32 i;

	if (!ad)
		REPORT_DISSECTOR_BUG("Null pointer passed to bytes_to_hexstr_punct()");

	out = byte_to_hex(out, ad[0]);
	for (i = 1; i < len; i++) {
		*out++ = punct;
		out = byte_to_hex(out, ad[i]);
	}
	return out;
}

/* Max string length for displaying byte string.  */
#define	MAX_BYTE_STR_LEN	48

/* Routine to convert a sequence of bytes to a hex string, one byte/two hex
 * digits at at a time, with a specified punctuation character between
 * the bytes.
 *
 * If punct is '\0', no punctuation is applied (and thus
 * the resulting string is (len-1) bytes shorter)
 */
gchar *
bytestring_to_str(wmem_allocator_t *scope, const guint8 *ad, const guint32 len, const char punct)
{
	gchar *buf;
	guint32 buflen = len;
	gchar *buf_ptr;
	int truncated = 0;

	if (!punct)
		return bytes_to_str(scope, ad, len);

	if (!ad)
		REPORT_DISSECTOR_BUG("Null pointer passed to bytestring_to_str()");

	if (len == 0)
		return wmem_strdup(scope, "");

	buf=(gchar *)wmem_alloc(scope, MAX_BYTE_STR_LEN+3+1);
	if (buflen > MAX_BYTE_STR_LEN/3) {	/* bd_len > 16 */
		truncated = 1;
		buflen = MAX_BYTE_STR_LEN/3;
	}

	buf_ptr = bytes_to_hexstr_punct(buf, ad, buflen, punct); /* max MAX_BYTE_STR_LEN-1 bytes */

	if (truncated) {
		*buf_ptr++ = punct;			/* 1 byte */
		buf_ptr    = g_stpcpy(buf_ptr, "...");	/* 3 bytes */
	}

	*buf_ptr = '\0';
	return buf;
}

char *
bytes_to_str(wmem_allocator_t *scope, const guint8 *bd, int bd_len)
{
	gchar *cur;
	gchar *cur_ptr;
	int truncated = 0;

	if (!bd)
		REPORT_DISSECTOR_BUG("Null pointer passed to bytes_to_str()");

	cur=(gchar *)wmem_alloc(scope, MAX_BYTE_STR_LEN+3+1);
	if (bd_len <= 0) { cur[0] = '\0'; return cur; }

	if (bd_len > MAX_BYTE_STR_LEN/2) {	/* bd_len > 24 */
		truncated = 1;
		bd_len = MAX_BYTE_STR_LEN/2;
	}

	cur_ptr = bytes_to_hexstr(cur, bd, bd_len);	/* max MAX_BYTE_STR_LEN bytes */

	if (truncated)
		cur_ptr = g_stpcpy(cur_ptr, "...");	/* 3 bytes */

	*cur_ptr = '\0';				/* 1 byte */
	return cur;
}

static int
guint32_to_str_buf_len(const guint32 u)
{
	/* ((2^32)-1) == 2147483647 */
	if (u >= 1000000000)return 10;
	if (u >= 100000000) return 9;
	if (u >= 10000000)  return 8;
	if (u >= 1000000)   return 7;
	if (u >= 100000)    return 6;
	if (u >= 10000)     return 5;
	if (u >= 1000)      return 4;
	if (u >= 100)       return 3;
	if (u >= 10)        return 2;

	return 1;
}

static int
guint64_to_str_buf_len(const guint64 u)
{
	/* ((2^64)-1) == 18446744073709551615 */

	if (u >= G_GUINT64_CONSTANT(10000000000000000000)) return 20;
	if (u >= G_GUINT64_CONSTANT(1000000000000000000))  return 19;
	if (u >= G_GUINT64_CONSTANT(100000000000000000))   return 18;
	if (u >= G_GUINT64_CONSTANT(10000000000000000))    return 17;
	if (u >= G_GUINT64_CONSTANT(1000000000000000))     return 16;
	if (u >= G_GUINT64_CONSTANT(100000000000000))      return 15;
	if (u >= G_GUINT64_CONSTANT(10000000000000))       return 14;
	if (u >= G_GUINT64_CONSTANT(1000000000000))        return 13;
	if (u >= G_GUINT64_CONSTANT(100000000000))         return 12;
	if (u >= G_GUINT64_CONSTANT(10000000000))          return 11;
	if (u >= G_GUINT64_CONSTANT(1000000000))           return 10;
	if (u >= G_GUINT64_CONSTANT(100000000))            return 9;
	if (u >= G_GUINT64_CONSTANT(10000000))             return 8;
	if (u >= G_GUINT64_CONSTANT(1000000))              return 7;
	if (u >= G_GUINT64_CONSTANT(100000))               return 6;
	if (u >= G_GUINT64_CONSTANT(10000))                return 5;
	if (u >= G_GUINT64_CONSTANT(1000))                 return 4;
	if (u >= G_GUINT64_CONSTANT(100))                  return 3;
	if (u >= G_GUINT64_CONSTANT(10))                   return 2;

	return 1;
}

static const char fast_strings[][4] = {
	"0", "1", "2", "3", "4", "5", "6", "7",
	"8", "9", "10", "11", "12", "13", "14", "15",
	"16", "17", "18", "19", "20", "21", "22", "23",
	"24", "25", "26", "27", "28", "29", "30", "31",
	"32", "33", "34", "35", "36", "37", "38", "39",
	"40", "41", "42", "43", "44", "45", "46", "47",
	"48", "49", "50", "51", "52", "53", "54", "55",
	"56", "57", "58", "59", "60", "61", "62", "63",
	"64", "65", "66", "67", "68", "69", "70", "71",
	"72", "73", "74", "75", "76", "77", "78", "79",
	"80", "81", "82", "83", "84", "85", "86", "87",
	"88", "89", "90", "91", "92", "93", "94", "95",
	"96", "97", "98", "99", "100", "101", "102", "103",
	"104", "105", "106", "107", "108", "109", "110", "111",
	"112", "113", "114", "115", "116", "117", "118", "119",
	"120", "121", "122", "123", "124", "125", "126", "127",
	"128", "129", "130", "131", "132", "133", "134", "135",
	"136", "137", "138", "139", "140", "141", "142", "143",
	"144", "145", "146", "147", "148", "149", "150", "151",
	"152", "153", "154", "155", "156", "157", "158", "159",
	"160", "161", "162", "163", "164", "165", "166", "167",
	"168", "169", "170", "171", "172", "173", "174", "175",
	"176", "177", "178", "179", "180", "181", "182", "183",
	"184", "185", "186", "187", "188", "189", "190", "191",
	"192", "193", "194", "195", "196", "197", "198", "199",
	"200", "201", "202", "203", "204", "205", "206", "207",
	"208", "209", "210", "211", "212", "213", "214", "215",
	"216", "217", "218", "219", "220", "221", "222", "223",
	"224", "225", "226", "227", "228", "229", "230", "231",
	"232", "233", "234", "235", "236", "237", "238", "239",
	"240", "241", "242", "243", "244", "245", "246", "247",
	"248", "249", "250", "251", "252", "253", "254", "255"
};

void
guint32_to_str_buf(guint32 u, gchar *buf, int buf_len)
{
	int str_len = guint32_to_str_buf_len(u)+1;

	gchar *bp = &buf[str_len];

	if (buf_len < str_len) {
		g_strlcpy(buf, BUF_TOO_SMALL_ERR, buf_len);	/* Let the unexpected value alert user */
		return;
	}

	*--bp = '\0';

	uint_to_str_back(bp, u);
}

void
guint64_to_str_buf(guint64 u, gchar *buf, int buf_len)
{
	int str_len = guint64_to_str_buf_len(u)+1;

	gchar *bp = &buf[str_len];

	if (buf_len < str_len) {
		g_strlcpy(buf, BUF_TOO_SMALL_ERR, buf_len);	/* Let the unexpected value alert user */
		return;
	}

	*--bp = '\0';

	uint64_to_str_back(bp, u);
}

static const char mon_names[12][4] = {
	"Jan",
	"Feb",
	"Mar",
	"Apr",
	"May",
	"Jun",
	"Jul",
	"Aug",
	"Sep",
	"Oct",
	"Nov",
	"Dec"
};

static const gchar *
get_zonename(struct tm *tmp)
{
#if defined(_WIN32)
	/* Windows C Runtime:                                                 */
	/*   _tzname is encoded using the "system default ansi code page"     */
	/*     ("which is not necessarily the same as the C library locale"). */
	/*     So: _tzname must be converted to UTF8 before use.              */
	/*   Alternative: use Windows GetTimeZoneInformation() to get the     */
	/*     timezone name in UTF16 and convert same to UTF8.               */
	/*   XXX: the result is that the timezone name will be based upon the */
	/*    system code page (iow: the charset of the system).              */
	/*    Since Wireshark is not internationalized, it would seem more    */
	/*    correct to show the timezone name in English, no matter what    */
	/*    the system code page, but I don't how to do that (or if it's    */
	/*    really even possible).                                          */
	/*    In any case converting to UTF8 presumably at least keeps GTK    */
	/*    happy. (A bug was reported wherein Wireshark crashed in GDK     */
	/*    on a "Japanese version of Windows XP" when trying to copy       */
	/*    the date/time string (containing a copy of _tz_name) to the     */
	/*    clipboard).                                                     */
	static char *ws_tzname[2] = {NULL, NULL};

	/* The g_malloc'd value returned from g_locale_to_utf8() is   */
	/*  cached for all further use so there's no need to ever     */
	/*  g_free() that value.                                      */
	if (ws_tzname[tmp->tm_isdst] == NULL) {
		ws_tzname[tmp->tm_isdst] = g_locale_to_utf8(_tzname[tmp->tm_isdst], -1, NULL, NULL, NULL);
		if (ws_tzname[tmp->tm_isdst] == NULL) {
			ws_tzname[tmp->tm_isdst] = "???";
		}
	}
	return ws_tzname[tmp->tm_isdst];
#else
	/*
	 * UN*X.
	 *
	 * If we have tm_zone in struct tm, use that.
	 * Otherwise, if we have tzname[], use it, otherwise just
	 * say "we don't know.
	 */
# if defined(HAVE_STRUCT_TM_TM_ZONE)
	return tmp->tm_zone;
# else /* HAVE_STRUCT_TM_TM_ZONE */
	if ((tmp->tm_isdst != 0) && (tmp->tm_isdst != 1)) {
		return "???";
	}
#  if defined(HAVE_TZNAME)
	return tzname[tmp->tm_isdst];
#  else
	return tmp->tm_isdst ? "?DT" : "?ST";
#  endif /* HAVE_TZNAME */
# endif /* HAVE_STRUCT_TM_TM_ZONE */
#endif /* _WIN32 */
}

gchar *
abs_time_to_str(wmem_allocator_t *scope, const nstime_t *abs_time, const absolute_time_display_e fmt,
		gboolean show_zone)
{
	struct tm *tmp = NULL;
	const char *zonename = "???";
	gchar *buf = NULL;


	switch (fmt) {

		case ABSOLUTE_TIME_UTC:
		case ABSOLUTE_TIME_DOY_UTC:
			tmp = gmtime(&abs_time->secs);
			zonename = "UTC";
			break;

		case ABSOLUTE_TIME_LOCAL:
			tmp = localtime(&abs_time->secs);
			if (tmp) {
				zonename = get_zonename(tmp);
			}
			break;
	}
	if (tmp) {
		switch (fmt) {

			case ABSOLUTE_TIME_DOY_UTC:
				if (show_zone) {
					buf = wmem_strdup_printf(scope,
							"%04d/%03d:%02d:%02d:%02d.%09ld %s",
							tmp->tm_year + 1900,
							tmp->tm_yday + 1,
							tmp->tm_hour,
							tmp->tm_min,
							tmp->tm_sec,
							(long)abs_time->nsecs,
							zonename);
				} else {
					buf = wmem_strdup_printf(scope,
							"%04d/%03d:%02d:%02d:%02d.%09ld",
							tmp->tm_year + 1900,
							tmp->tm_yday + 1,
							tmp->tm_hour,
							tmp->tm_min,
							tmp->tm_sec,
							(long)abs_time->nsecs);
				}
				break;

			case ABSOLUTE_TIME_UTC:
			case ABSOLUTE_TIME_LOCAL:
				if (show_zone) {
					buf = wmem_strdup_printf(scope,
							"%s %2d, %d %02d:%02d:%02d.%09ld %s",
							mon_names[tmp->tm_mon],
							tmp->tm_mday,
							tmp->tm_year + 1900,
							tmp->tm_hour,
							tmp->tm_min,
							tmp->tm_sec,
							(long)abs_time->nsecs,
							zonename);
				} else {
					buf = wmem_strdup_printf(scope,
							"%s %2d, %d %02d:%02d:%02d.%09ld",
							mon_names[tmp->tm_mon],
							tmp->tm_mday,
							tmp->tm_year + 1900,
							tmp->tm_hour,
							tmp->tm_min,
							tmp->tm_sec,
							(long)abs_time->nsecs);
				}
				break;
		}
	} else
		buf = wmem_strdup(scope, "Not representable");
	return buf;
}

gchar *
abs_time_secs_to_str(wmem_allocator_t *scope, const time_t abs_time, const absolute_time_display_e fmt,
		gboolean show_zone)
{
	struct tm *tmp = NULL;
	const char *zonename = "???";
	gchar *buf = NULL;

	switch (fmt) {

		case ABSOLUTE_TIME_UTC:
		case ABSOLUTE_TIME_DOY_UTC:
			tmp = gmtime(&abs_time);
			zonename = "UTC";
			break;

		case ABSOLUTE_TIME_LOCAL:
			tmp = localtime(&abs_time);
			if (tmp) {
				zonename = get_zonename(tmp);
			}
			break;
	}
	if (tmp) {
		switch (fmt) {

			case ABSOLUTE_TIME_DOY_UTC:
				if (show_zone) {
					buf = wmem_strdup_printf(scope,
							"%04d/%03d:%02d:%02d:%02d %s",
							tmp->tm_year + 1900,
							tmp->tm_yday + 1,
							tmp->tm_hour,
							tmp->tm_min,
							tmp->tm_sec,
							zonename);
				} else {
					buf = wmem_strdup_printf(scope,
							"%04d/%03d:%02d:%02d:%02d",
							tmp->tm_year + 1900,
							tmp->tm_yday + 1,
							tmp->tm_hour,
							tmp->tm_min,
							tmp->tm_sec);
				}
				break;

			case ABSOLUTE_TIME_UTC:
			case ABSOLUTE_TIME_LOCAL:
				if (show_zone) {
					buf = wmem_strdup_printf(scope,
							"%s %2d, %d %02d:%02d:%02d %s",
							mon_names[tmp->tm_mon],
							tmp->tm_mday,
							tmp->tm_year + 1900,
							tmp->tm_hour,
							tmp->tm_min,
							tmp->tm_sec,
							zonename);
				} else {
					buf = wmem_strdup_printf(scope,
							"%s %2d, %d %02d:%02d:%02d",
							mon_names[tmp->tm_mon],
							tmp->tm_mday,
							tmp->tm_year + 1900,
							tmp->tm_hour,
							tmp->tm_min,
							tmp->tm_sec);
				}
				break;
		}
	} else
		buf = wmem_strdup(scope, "Not representable");
	return buf;
}

void
display_epoch_time(gchar *buf, int buflen, const time_t sec, gint32 frac,
		const to_str_time_res_t units)
{
	double elapsed_secs;

	elapsed_secs = difftime(sec,(time_t)0);

	/* This code copied from display_signed_time; keep it in case anyone
	   is looking at captures from before 1970 (???).
	   If the fractional part of the time stamp is negative,
	   print its absolute value and, if the seconds part isn't
	   (the seconds part should be zero in that case), stick
	   a "-" in front of the entire time stamp. */
	if (frac < 0) {
		frac = -frac;
		if (elapsed_secs >= 0) {
			if (buflen < 1) {
				return;
			}
			buf[0] = '-';
			buf++;
			buflen--;
		}
	}
	switch (units) {

		case TO_STR_TIME_RES_T_SECS:
			g_snprintf(buf, buflen, "%0.0f", elapsed_secs);
			break;

		case TO_STR_TIME_RES_T_DSECS:
			g_snprintf(buf, buflen, "%0.0f.%01d", elapsed_secs, frac);
			break;

		case TO_STR_TIME_RES_T_CSECS:
			g_snprintf(buf, buflen, "%0.0f.%02d", elapsed_secs, frac);
			break;

		case TO_STR_TIME_RES_T_MSECS:
			g_snprintf(buf, buflen, "%0.0f.%03d", elapsed_secs, frac);
			break;

		case TO_STR_TIME_RES_T_USECS:
			g_snprintf(buf, buflen, "%0.0f.%06d", elapsed_secs, frac);
			break;

		case TO_STR_TIME_RES_T_NSECS:
			g_snprintf(buf, buflen, "%0.0f.%09d", elapsed_secs, frac);
			break;
	}
}

void
display_signed_time(gchar *buf, int buflen, const gint32 sec, gint32 frac,
		const to_str_time_res_t units)
{
	/* this buffer is not NUL terminated */
	gint8 num_buf[16]; /* max: '-2147483648', '.1000000000' */
	gint8 *num_end = &num_buf[16];
	gint8 *num_ptr;
	int num_len;

	if (buflen < 1)
		return;

	/* If the fractional part of the time stamp is negative,
	   print its absolute value and, if the seconds part isn't
	   (the seconds part should be zero in that case), stick
	   a "-" in front of the entire time stamp. */
	if (frac < 0) {
		frac = -frac;
		if (sec >= 0) {
			buf[0] = '-';
			buf++;
			buflen--;
		}
	}

	num_ptr = int_to_str_back(num_end, sec);

	num_len = MIN((int) (num_end - num_ptr), buflen);
	memcpy(buf, num_ptr, num_len);
	buf += num_len;
	buflen -= num_len;

	switch (units) {
		case TO_STR_TIME_RES_T_SECS:
		default:
			/* no fraction */
			num_ptr = NULL;
			break;

		case TO_STR_TIME_RES_T_DSECS:
			num_ptr = uint_to_str_back_len(num_end, frac, 1);
			break;

		case TO_STR_TIME_RES_T_CSECS:
			num_ptr = uint_to_str_back_len(num_end, frac, 2);
			break;

		case TO_STR_TIME_RES_T_MSECS:
			num_ptr = uint_to_str_back_len(num_end, frac, 3);
			break;

		case TO_STR_TIME_RES_T_USECS:
			num_ptr = uint_to_str_back_len(num_end, frac, 6);
			break;

		case TO_STR_TIME_RES_T_NSECS:
			num_ptr = uint_to_str_back_len(num_end, frac, 9);
			break;
	}

	if (num_ptr != NULL)
	{
		*(--num_ptr) = '.';

		num_len = MIN((int) (num_end - num_ptr), buflen);
		memcpy(buf, num_ptr, num_len);
		buf += num_len;
		buflen -= num_len;
	}

	/* need to NUL terminate, we know that buffer had at least 1 byte */
	if (buflen == 0)
		buf--;
	*buf = '\0';
}

#define	PLURALIZE(n)	(((n) > 1) ? "s" : "")
#define	COMMA(do_it)	((do_it) ? ", " : "")

/*
 * Maximum length of a string showing days/hours/minutes/seconds.
 * (Does not include the terminating '\0'.)
 * Includes space for a '-' sign for any negative components.
 * -12345 days, 12 hours, 12 minutes, 12.123 seconds
 */
#define TIME_SECS_LEN	(10+1+4+2+2+5+2+2+7+2+2+7+4)

/*
 * Convert an unsigned value in seconds and fractions of a second to a string,
 * giving time in days, hours, minutes, and seconds, and put the result
 * into a buffer.
 * "is_nsecs" says that "frac" is nanoseconds if true and milliseconds
 * if false.
 */
static void
unsigned_time_secs_to_str_buf(guint32 time_val, const guint32 frac,
    const gboolean is_nsecs, wmem_strbuf_t *buf)
{
	int hours, mins, secs;
	gboolean do_comma = FALSE;

	secs = time_val % 60;
	time_val /= 60;
	mins = time_val % 60;
	time_val /= 60;
	hours = time_val % 24;
	time_val /= 24;

	if (time_val != 0) {
		wmem_strbuf_append_printf(buf, "%u day%s", time_val, PLURALIZE(time_val));
		do_comma = TRUE;
	}
	if (hours != 0) {
		wmem_strbuf_append_printf(buf, "%s%u hour%s", COMMA(do_comma), hours, PLURALIZE(hours));
		do_comma = TRUE;
	}
	if (mins != 0) {
		wmem_strbuf_append_printf(buf, "%s%u minute%s", COMMA(do_comma), mins, PLURALIZE(mins));
		do_comma = TRUE;
	}
	if (secs != 0 || frac != 0) {
		if (frac != 0) {
			if (is_nsecs)
				wmem_strbuf_append_printf(buf, "%s%u.%09u seconds", COMMA(do_comma), secs, frac);
			else
				wmem_strbuf_append_printf(buf, "%s%u.%03u seconds", COMMA(do_comma), secs, frac);
		} else
			wmem_strbuf_append_printf(buf, "%s%u second%s", COMMA(do_comma), secs, PLURALIZE(secs));
	}
}

gchar *
unsigned_time_secs_to_str(wmem_allocator_t *scope, const guint32 time_val)
{
	wmem_strbuf_t *buf;

	if (time_val == 0) {
		return wmem_strdup(scope, "0 seconds");
	}

	buf = wmem_strbuf_sized_new(scope, TIME_SECS_LEN+1, TIME_SECS_LEN+1);

	unsigned_time_secs_to_str_buf(time_val, 0, FALSE, buf);

	return wmem_strbuf_finalize(buf);
}

/*
 * Convert a signed value in seconds and fractions of a second to a string,
 * giving time in days, hours, minutes, and seconds, and put the result
 * into a buffer.
 * "is_nsecs" says that "frac" is nanoseconds if true and milliseconds
 * if false.
 */
static void
signed_time_secs_to_str_buf(gint32 time_val, const guint32 frac,
    const gboolean is_nsecs, wmem_strbuf_t *buf)
{
	if(time_val < 0){
		wmem_strbuf_append_printf(buf, "-");
		if(time_val == G_MININT32) {
			/*
			 * You can't fit time_val's absolute value into
			 * a 32-bit signed integer.  Just directly
			 * pass G_MAXUINT32, which is its absolute
			 * value, directly to unsigned_time_secs_to_str_buf().
			 *
			 * (XXX - does ISO C guarantee that -(-2^n),
			 * when calculated and cast to an n-bit unsigned
			 * integer type, will have the value 2^n?)
			 */
			unsigned_time_secs_to_str_buf(G_MAXUINT32, frac,
			    is_nsecs, buf);
		} else {
			/*
			 * We now know -secs will fit into a guint32;
			 * negate it and pass that to
			 * unsigned_time_secs_to_str_buf().
			 */
			unsigned_time_secs_to_str_buf(-time_val, frac,
			    is_nsecs, buf);
		}
	} else
		unsigned_time_secs_to_str_buf(time_val, frac, is_nsecs, buf);
}

gchar *
signed_time_secs_to_str(wmem_allocator_t *scope, const gint32 time_val)
{
	wmem_strbuf_t *buf;

	if (time_val == 0) {
		return wmem_strdup(scope, "0 seconds");
	}

	buf = wmem_strbuf_sized_new(scope, TIME_SECS_LEN+1, TIME_SECS_LEN+1);

	signed_time_secs_to_str_buf(time_val, 0, FALSE, buf);

	return wmem_strbuf_finalize(buf);
}

/*
 * Convert a signed value in milliseconds to a string, giving time in days,
 * hours, minutes, and seconds, and put the result into a buffer.
 */
gchar *
signed_time_msecs_to_str(wmem_allocator_t *scope, gint32 time_val)
{
	wmem_strbuf_t *buf;
	int msecs;

	if (time_val == 0) {
		return wmem_strdup(scope, "0 seconds");
	}

	buf = wmem_strbuf_sized_new(scope, TIME_SECS_LEN+1+3+1, TIME_SECS_LEN+1+3+1);

	if (time_val<0) {
		/* oops we got passed a negative time */
		time_val= -time_val;
		msecs = time_val % 1000;
		time_val /= 1000;
		time_val= -time_val;
	} else {
		msecs = time_val % 1000;
		time_val /= 1000;
	}

	signed_time_secs_to_str_buf(time_val, msecs, FALSE, buf);

	return wmem_strbuf_finalize(buf);
}

/*
 * Display a relative time as days/hours/minutes/seconds.
 */
gchar *
rel_time_to_str(wmem_allocator_t *scope, const nstime_t *rel_time)
{
	wmem_strbuf_t *buf;
	gint32 time_val;
	gint32 nsec;

	/* If the nanoseconds part of the time stamp is negative,
	   print its absolute value and, if the seconds part isn't
	   (the seconds part should be zero in that case), stick
	   a "-" in front of the entire time stamp. */
	time_val = (gint) rel_time->secs;
	nsec = rel_time->nsecs;
	if (time_val == 0 && nsec == 0) {
		return wmem_strdup(scope, "0.000000000 seconds");
	}

	buf = wmem_strbuf_sized_new(scope, 1+TIME_SECS_LEN+1+6+1, 1+TIME_SECS_LEN+1+6+1);

	if (nsec < 0) {
		nsec = -nsec;
		wmem_strbuf_append_c(buf, '-');

		/*
		 * We assume here that "rel_time->secs" is negative
		 * or zero; if it's not, the time stamp is bogus,
		 * with a positive seconds and negative microseconds.
		 */
		time_val = (gint) -rel_time->secs;
	}

	signed_time_secs_to_str_buf(time_val, nsec, TRUE, buf);

	return wmem_strbuf_finalize(buf);
}

#define REL_TIME_SECS_LEN	(1+10+1+9+1)

/*
 * Display a relative time as seconds.
 */
gchar *
rel_time_to_secs_str(wmem_allocator_t *scope, const nstime_t *rel_time)
{
	gchar *buf;

	buf=(gchar *)wmem_alloc(scope, REL_TIME_SECS_LEN);

	display_signed_time(buf, REL_TIME_SECS_LEN, (gint32) rel_time->secs,
			rel_time->nsecs, TO_STR_TIME_RES_T_NSECS);
	return buf;
}

/*
 * Generates a string representing the bits in a bitfield at "bit_offset" from an 8 bit boundary
 * with the length in bits of no_of_bits based on value.
 * Ex: ..xx x...
 */

char *
decode_bits_in_field(const guint bit_offset, const gint no_of_bits, const guint64 value)
{
	guint64 mask = 0,tmp;
	char *str;
	int bit, str_p = 0;
	int i;

	mask = 1;
	mask = mask << (no_of_bits-1);

	/* Prepare the string, 256 pos for the bits and zero termination, + 64 for the spaces */
	str=(char *)wmem_alloc0(wmem_packet_scope(), 256+64);
	for(bit=0;bit<((int)(bit_offset&0x07));bit++){
		if(bit&&(!(bit%4))){
			str[str_p] = ' ';
			str_p++;
		}
		str[str_p] = '.';
		str_p++;
	}

	/* read the bits for the int */
	for(i=0;i<no_of_bits;i++){
		if(bit&&(!(bit%4))){
			str[str_p] = ' ';
			str_p++;
		}
		if(bit&&(!(bit%8))){
			str[str_p] = ' ';
			str_p++;
		}
		bit++;
		tmp = value & mask;
		if(tmp != 0){
			str[str_p] = '1';
			str_p++;
		} else {
			str[str_p] = '0';
			str_p++;
		}
		mask = mask>>1;
	}

	for(;bit%8;bit++){
		if(bit&&(!(bit%4))){
			str[str_p] = ' ';
			str_p++;
		}
		str[str_p] = '.';
		str_p++;
	}
	return str;
}

/*
   This function is very fast and this function is called a lot.
   XXX update the address_to_str stuff to use this function.
   */
void
ip_to_str_buf(const guint8 *ad, gchar *buf, const int buf_len)
{
	register gchar const *p;
	register gchar *b=buf;

	if (buf_len < MAX_IP_STR_LEN) {
		g_strlcpy(buf, BUF_TOO_SMALL_ERR, buf_len);  /* Let the unexpected value alert user */
		return;
	}

	p=fast_strings[*ad++];
	do {
		*b++=*p;
		p++;
	} while(*p);
	*b++='.';

	p=fast_strings[*ad++];
	do {
		*b++=*p;
		p++;
	} while(*p);
	*b++='.';

	p=fast_strings[*ad++];
	do {
		*b++=*p;
		p++;
	} while(*p);
	*b++='.';

	p=fast_strings[*ad];
	do {
		*b++=*p;
		p++;
	} while(*p);
	*b=0;
}

void
ip6_to_str_buf(const struct e_in6_addr *ad, gchar *buf, int buf_len)
{
	if (buf_len < WS_INET6_ADDRSTRLEN) {
		g_strlcpy(buf, BUF_TOO_SMALL_ERR, buf_len);  /* Let the unexpected value alert user */
		return;
	}

	ws_inet_ntop6(ad, buf, buf_len);
}

gchar *
guid_to_str(wmem_allocator_t *scope, const e_guid_t *guid)
{
	gchar *buf;

	buf=(gchar *)wmem_alloc(scope, GUID_STR_LEN);
	return guid_to_str_buf(guid, buf, GUID_STR_LEN);
}

gchar *
guid_to_str_buf(const e_guid_t *guid, gchar *buf, int buf_len)
{
	char *tempptr = buf;

	if (buf_len < GUID_STR_LEN) {
		g_strlcpy(buf, BUF_TOO_SMALL_ERR, buf_len);/* Let the unexpected value alert user */
		return buf;
	}

	/* 37 bytes */
	tempptr    = dword_to_hex(tempptr, guid->data1);		/*  8 bytes */
	*tempptr++ = '-';						/*  1 byte */
	tempptr    = word_to_hex(tempptr, guid->data2);			/*  4 bytes */
	*tempptr++ = '-';						/*  1 byte */
	tempptr    = word_to_hex(tempptr, guid->data3);			/*  4 bytes */
	*tempptr++ = '-';						/*  1 byte */
	tempptr    = bytes_to_hexstr(tempptr, &guid->data4[0], 2);	/*  4 bytes */
	*tempptr++ = '-';						/*  1 byte */
	tempptr    = bytes_to_hexstr(tempptr, &guid->data4[2], 6);	/* 12 bytes */

	*tempptr   = '\0';
	return buf;
}

gchar *
eui64_to_str(wmem_allocator_t *scope, const guint64 ad) {
	gchar *buf, *tmp;
	guint8 *p_eui64;

	p_eui64=(guint8 *)wmem_alloc(NULL, 8);
	buf=(gchar *)wmem_alloc(scope, EUI64_STR_LEN);

	/* Copy and convert the address to network byte order. */
	*(guint64 *)(void *)(p_eui64) = pntoh64(&(ad));

	tmp = bytes_to_hexstr_punct(buf, p_eui64, 8, ':');
	*tmp = '\0'; /* NULL terminate */
	wmem_free(NULL, p_eui64);
	return buf;
}

const gchar *
port_type_to_str (port_type type)
{
	switch (type) {
		case PT_NONE:		return "NONE";
		case PT_SCTP:		return "SCTP";
		case PT_TCP:		return "TCP";
		case PT_UDP:		return "UDP";
		case PT_DCCP:		return "DCCP";
		case PT_IPX:		return "IPX";
		case PT_NCP:		return "NCP";
		case PT_EXCHG:		return "FC EXCHG";
		case PT_DDP:		return "DDP";
		case PT_SBCCS:		return "FICON SBCCS";
		case PT_IDP:		return "IDP";
		case PT_TIPC:		return "TIPC";
		case PT_USB:		return "USB";
		case PT_I2C:		return "I2C";
		case PT_IBQP:		return "IBQP";
		case PT_BLUETOOTH:	return "BLUETOOTH";
		case PT_TDMOP:		return "TDMOP";
		default:		return "[Unknown]";
	}
}

char *
oct_to_str_back(char *ptr, guint32 value)
{
	while (value) {
		*(--ptr) = '0' + (value & 0x7);
		value >>= 3;
	}

	*(--ptr) = '0';
	return ptr;
}

char *
oct64_to_str_back(char *ptr, guint64 value)
{
	while (value) {
		*(--ptr) = '0' + (value & 0x7);
		value >>= 3;
	}

	*(--ptr) = '0';
	return ptr;
}

char *
hex_to_str_back(char *ptr, int len, guint32 value)
{
	do {
		*(--ptr) = low_nibble_of_octet_to_hex(value);
		value >>= 4;
		len--;
	} while (value);

	/* pad */
	while (len > 0) {
		*(--ptr) = '0';
		len--;
	}

	*(--ptr) = 'x';
	*(--ptr) = '0';

	return ptr;
}

char *
hex64_to_str_back(char *ptr, int len, guint64 value)
{
	do {
		*(--ptr) = low_nibble_of_octet_to_hex(value & 0xF);
		value >>= 4;
		len--;
	} while (value);

	/* pad */
	while (len > 0) {
		*(--ptr) = '0';
		len--;
	}

	*(--ptr) = 'x';
	*(--ptr) = '0';

	return ptr;
}

char *
uint_to_str_back(char *ptr, guint32 value)
{
	char const *p;

	/* special case */
	if (value == 0)
		*(--ptr) = '0';

	while (value >= 10) {
		p = fast_strings[100 + (value % 100)];

		value /= 100;

		*(--ptr) = p[2];
		*(--ptr) = p[1];
	}

	if (value)
		*(--ptr) = (value) | '0';

	return ptr;
}

char *
uint64_to_str_back(char *ptr, guint64 value)
{
	char const *p;

	/* special case */
	if (value == 0)
		*(--ptr) = '0';

	while (value >= 10) {
		p = fast_strings[100 + (value % 100)];

		value /= 100;

		*(--ptr) = p[2];
		*(--ptr) = p[1];
	}

	/* value will be 0..9, so using '& 0xF' is safe, and faster than '% 10' */
	if (value)
		*(--ptr) = (value & 0xF) | '0';

	return ptr;
}

char *
uint_to_str_back_len(char *ptr, guint32 value, int len)
{
	char *new_ptr;

	new_ptr = uint_to_str_back(ptr, value);

	/* substract from len number of generated characters */
	len -= (int)(ptr - new_ptr);

	/* pad remaining with '0' */
	while (len > 0)
	{
		*(--new_ptr) = '0';
		len--;
	}

	return new_ptr;
}

char *
uint64_to_str_back_len(char *ptr, guint64 value, int len)
{
	char *new_ptr;

	new_ptr = uint64_to_str_back(ptr, value);

	/* substract from len number of generated characters */
	len -= (int)(ptr - new_ptr);

	/* pad remaining with '0' */
	while (len > 0)
	{
		*(--new_ptr) = '0';
		len--;
	}

	return new_ptr;
}

char *
int_to_str_back(char *ptr, gint32 value)
{
	if (value < 0) {
		ptr = uint_to_str_back(ptr, -value);
		*(--ptr) = '-';
	} else
		ptr = uint_to_str_back(ptr, value);

	return ptr;
}

char *
int64_to_str_back(char *ptr, gint64 value)
{
	if (value < 0) {
		ptr = uint64_to_str_back(ptr, -value);
		*(--ptr) = '-';
	} else
		ptr = uint64_to_str_back(ptr, value);

	return ptr;
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
