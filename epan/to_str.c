/* to_str.c
 * Routines for utilities to convert various other types to strings.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <glib.h>

#include "emem.h"
#include "proto.h"
#include "to_str.h"

/*
 * If a user _does_ pass in a too-small buffer, this is probably
 * going to be too long to fit.  However, even a partial string
 * starting with "[Buf" should provide enough of a clue to be
 * useful.
 */
#define BUF_TOO_SMALL_ERR "[Buffer too small]"

static inline char *
byte_to_hex(char *out, guint32 dword) {
  /* At least one version of Apple's C compiler/linker is buggy, causing
     a complaint from the linker about the "literal C string section"
     not ending with '\0' if we initialize a 16-element "char" array with
     a 16-character string, the fact that initializing such an array with
     such a string is perfectly legitimate ANSI C nonwithstanding, the 17th
     '\0' byte in the string nonwithstanding. */
  static const gchar hex_digits[16] =
      { '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

  *out++ = hex_digits[(dword >> 4) & 0xF];
  *out++ = hex_digits[dword & 0xF];
  return out;
}

char *
word_to_hex(char *out, guint16 word) {
  out = byte_to_hex(out, word >> 8);
  out = byte_to_hex(out, word);
  return out;
}

char *
word_to_hex_npad(char *out, guint16 word) {
  static const gchar hex_digits[16] =
      { '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

	if (word >= 0x1000)
		*out++ = hex_digits[(word >> 12) & 0xF];
	if (word >= 0x0100)
		*out++ = hex_digits[(word >> 8) & 0xF];
	if (word >= 0x0010)
		*out++ = hex_digits[(word >> 4) & 0xF];
	*out++ = hex_digits[word & 0xF];
	return out;
}

char *
dword_to_hex(char *out, guint32 dword) {
  out = byte_to_hex(out, dword >> 24);
  out = byte_to_hex(out, dword >> 16);
  out = byte_to_hex(out, dword >>  8);
  out = byte_to_hex(out, dword);
  return out;
}

char *
dword_to_hex_punct(char *out, guint32 dword, char punct) {
  out = byte_to_hex(out, dword >> 24);
  *out++ = punct;
  out = byte_to_hex(out, dword >> 16);
  *out++ = punct;
  out = byte_to_hex(out, dword >>  8);
  *out++ = punct;
  out = byte_to_hex(out, dword);
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
bytes_to_hexstr(char *out, const guint8 *ad, guint32 len) {
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
bytes_to_hexstr_punct(char *out, const guint8 *ad, guint32 len, char punct) {
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

/* Routine to convert a sequence of bytes to a hex string, one byte/two hex
 * digits at at a time, with a specified punctuation character between
 * the bytes.
 *
 * If punct is '\0', no punctuation is applied (and thus
 * the resulting string is (len-1) bytes shorter)
 */
gchar *
bytestring_to_str(const guint8 *ad, const guint32 len, const char punct) {
  gchar *buf;
  size_t       buflen;

  if (!ad)
    REPORT_DISSECTOR_BUG("Null pointer passed to bytestring_to_str()");

  /* XXX, Old code was using int as iterator... Why len is guint32 anyway?! (darkjames) */
  if ( ((int) len) < 0)
     return "";

  if (!len)
     return "";

  if (punct)
    buflen=len*3;
  else
    buflen=len*2 + 1;

  buf=ep_alloc(buflen);

  if (punct)
    bytes_to_hexstr_punct(buf, ad, len, punct);
  else
    bytes_to_hexstr(buf, ad, len);

  buf[buflen-1] = '\0';
  return buf;
}

/* Max string length for displaying byte string.  */
#define	MAX_BYTE_STR_LEN	48

gchar *
bytes_to_str(const guint8 *bd, int bd_len) {
  gchar *cur;
  gchar *cur_ptr;
  int truncated = 0;

  if (!bd)
    REPORT_DISSECTOR_BUG("Null pointer passed to bytes_to_str()");

  cur=ep_alloc(MAX_BYTE_STR_LEN+3+1);
  if (bd_len <= 0) { cur[0] = '\0'; return cur; }

  if (bd_len > MAX_BYTE_STR_LEN/2) {	/* bd_len > 24 */
    truncated = 1;
    bd_len = MAX_BYTE_STR_LEN/2;
  }

  cur_ptr = bytes_to_hexstr(cur, bd, bd_len);	/* max MAX_BYTE_STR_LEN bytes */

  if (truncated)
    cur_ptr = g_stpcpy(cur_ptr, "...");		/* 3 bytes */

  *cur_ptr = '\0';				/* 1 byte */
  return cur;
}

/* Turn an array of bytes into a string showing the bytes in hex with
 * punct as a bytes separator.
 */
gchar *
bytes_to_str_punct(const guint8 *bd, int bd_len, gchar punct) {
  gchar *cur;
  gchar *cur_ptr;
  int truncated = 0;

  if (!punct)
    return bytes_to_str(bd, bd_len);

  cur=ep_alloc(MAX_BYTE_STR_LEN+3+1);
  if (bd_len <= 0) { cur[0] = '\0'; return cur; }

  if (bd_len > MAX_BYTE_STR_LEN/3) {	/* bd_len > 16 */
   truncated = 1;
   bd_len = MAX_BYTE_STR_LEN/3;
  }

  cur_ptr = bytes_to_hexstr_punct(cur, bd, bd_len, punct); /* max MAX_BYTE_STR_LEN-1 bytes */

  if (truncated) {
    *cur_ptr++ = punct;				/* 1 byte */
    cur_ptr    = g_stpcpy(cur_ptr, "...");	/* 3 bytes */
  }

  *cur_ptr = '\0';
  return cur;
}

static int
guint32_to_str_buf_len(const guint32 u) {
    if (u >= 1000000000)return 10;
    if (u >= 100000000) return 9;
    if (u >= 10000000)	return 8;
    if (u >= 1000000)	return 7;
    if (u >= 100000)	return 6;
    if (u >= 10000)	return 5;
    if (u >= 1000)	return 4;
    if (u >= 100)	return 3;
    if (u >= 10)	return 2;

    return 1;
}

static const char * const fast_strings[] = {
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
guint32_to_str_buf(guint32 u, gchar *buf, int buf_len) {
  int str_len = guint32_to_str_buf_len(u)+1;

  gchar *bp = &buf[str_len];
  gchar const *p;

  if (buf_len < str_len) {
    g_strlcpy(buf, BUF_TOO_SMALL_ERR, buf_len);	/* Let the unexpected value alert user */
    return;
  }

  *--bp = '\0';

  while (u >= 10) {
    p = fast_strings[100 + (u % 100)];

    *--bp = p[2];
    *--bp = p[1];

    u /= 100;
  }

  if (bp != buf) /* ugly, fixme! */
    *--bp = (u % 10) | '0';
}

gchar *
guint32_to_str(const guint32 u) {
  int str_len = 16; /* guint32_to_str_buf_len(u)+1; */

  gchar *bp = ep_alloc(str_len);
  guint32_to_str_buf(u, bp, str_len);

  return bp;
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
 * Convert a value in seconds and fractions of a second to a string,
 * giving time in days, hours, minutes, and seconds, and put the result
 * into a buffer.
 * "is_nsecs" says that "frac" is microseconds if true and milliseconds
 * if false.
 * If time is negative, add a '-' to all non-null components.
 */
static void
time_secs_to_str_buf(gint32 time_val, const guint32 frac, const gboolean is_nsecs,
			   emem_strbuf_t *buf)
{
  int hours, mins, secs;
  const gchar *msign = "";
  gboolean do_comma = FALSE;

  if(time_val == G_MININT32) {	/* That Which Shall Not Be Negated */
    ep_strbuf_append_printf(buf, "Unable to cope with time value %d", time_val);
    return;
  }

  if(time_val < 0){
    time_val = -time_val;
    msign = "-";
  }

  secs = time_val % 60;
  time_val /= 60;
  mins = time_val % 60;
  time_val /= 60;
  hours = time_val % 24;
  time_val /= 24;

  if (time_val != 0) {
    ep_strbuf_append_printf(buf, "%s%u day%s", msign, time_val, PLURALIZE(time_val));
    do_comma = TRUE;
    msign="";
  }
  if (hours != 0) {
    ep_strbuf_append_printf(buf, "%s%s%u hour%s", COMMA(do_comma), msign, hours, PLURALIZE(hours));
    do_comma = TRUE;
    msign="";
  }
  if (mins != 0) {
    ep_strbuf_append_printf(buf, "%s%s%u minute%s", COMMA(do_comma), msign, mins, PLURALIZE(mins));
    do_comma = TRUE;
    msign="";
  }
  if (secs != 0 || frac != 0) {
    if (frac != 0) {
      if (is_nsecs)
        ep_strbuf_append_printf(buf, "%s%s%u.%09u seconds", COMMA(do_comma), msign, secs, frac);
      else
        ep_strbuf_append_printf(buf, "%s%s%u.%03u seconds", COMMA(do_comma), msign, secs, frac);
    } else
      ep_strbuf_append_printf(buf, "%s%s%u second%s", COMMA(do_comma), msign, secs, PLURALIZE(secs));
  }
}

gchar *
time_secs_to_str(const gint32 time_val)
{
  emem_strbuf_t *buf;

  buf=ep_strbuf_sized_new(TIME_SECS_LEN+1, TIME_SECS_LEN+1);

  if (time_val == 0) {
    ep_strbuf_append(buf, "0 seconds");
    return buf->str;
  }

  time_secs_to_str_buf(time_val, 0, FALSE, buf);
  return buf->str;
}

static void
time_secs_to_str_buf_unsigned(guint32 time_val, const guint32 frac, const gboolean is_nsecs,
			 emem_strbuf_t *buf)
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
    ep_strbuf_append_printf(buf, "%u day%s", time_val, PLURALIZE(time_val));
    do_comma = TRUE;
  }
  if (hours != 0) {
    ep_strbuf_append_printf(buf, "%s%u hour%s", COMMA(do_comma), hours, PLURALIZE(hours));
    do_comma = TRUE;
  }
  if (mins != 0) {
    ep_strbuf_append_printf(buf, "%s%u minute%s", COMMA(do_comma), mins, PLURALIZE(mins));
    do_comma = TRUE;
  }
  if (secs != 0 || frac != 0) {
    if (frac != 0) {
      if (is_nsecs)
        ep_strbuf_append_printf(buf, "%s%u.%09u seconds", COMMA(do_comma), secs, frac);
      else
        ep_strbuf_append_printf(buf, "%s%u.%03u seconds", COMMA(do_comma), secs, frac);
    } else
      ep_strbuf_append_printf(buf, "%s%u second%s", COMMA(do_comma), secs, PLURALIZE(secs));
  }
}

gchar *
time_secs_to_str_unsigned(const guint32 time_val)
{
  emem_strbuf_t *buf;

  buf=ep_strbuf_sized_new(TIME_SECS_LEN+1, TIME_SECS_LEN+1);

  if (time_val == 0) {
    ep_strbuf_append(buf, "0 seconds");
    return buf->str;
  }

  time_secs_to_str_buf_unsigned(time_val, 0, FALSE, buf);
  return buf->str;
}


gchar *
time_msecs_to_str(gint32 time_val)
{
  emem_strbuf_t *buf;
  int msecs;

  buf=ep_strbuf_sized_new(TIME_SECS_LEN+1+3+1, TIME_SECS_LEN+1+3+1);

  if (time_val == 0) {
    ep_strbuf_append(buf, "0 seconds");
    return buf->str;
  }

  if(time_val<0){
    /* oops we got passed a negative time */
    time_val= -time_val;
    msecs = time_val % 1000;
    time_val /= 1000;
    time_val= -time_val;
  } else {
    msecs = time_val % 1000;
    time_val /= 1000;
  }

  time_secs_to_str_buf(time_val, msecs, FALSE, buf);
  return buf->str;
}

static const char *mon_names[12] = {
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

static const gchar *get_zonename(struct tm *tmp) {
#if defined(HAVE_TM_ZONE)
	return tmp->tm_zone;
#else
	if ((tmp->tm_isdst != 0) && (tmp->tm_isdst != 1)) {
		return "???";
	}
# if defined(HAVE_TZNAME)
	return tzname[tmp->tm_isdst];

# elif defined(_WIN32)
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

	{
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
	}
# else
	return tmp->tm_isdst ? "?DT" : "?ST";

# endif
#endif
}

gchar *
abs_time_to_str(const nstime_t *abs_time, const absolute_time_display_e fmt,
   gboolean show_zone)
{
        struct tm *tmp = NULL;
        const char *zonename = "???";
        gchar *buf = NULL;

#ifdef _MSC_VER
        /* calling localtime() on MSVC 2005 with huge values causes it to crash */
        /* XXX - find the exact value that still does work */
        /* XXX - using _USE_32BIT_TIME_T might be another way to circumvent this problem */
        if(abs_time->secs > 2000000000) {
            tmp = NULL;
        } else
#endif
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
	                        buf = ep_strdup_printf("%04d/%03d:%02d:%02d:%02d.%09ld %s",
        	                    tmp->tm_year + 1900,
                	            tmp->tm_yday + 1,
                        	    tmp->tm_hour,
	                            tmp->tm_min,
        	                    tmp->tm_sec,
                	            (long)abs_time->nsecs,
                        	    zonename);
                        } else {
	                        buf = ep_strdup_printf("%04d/%03d:%02d:%02d:%02d.%09ld",
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
	                        buf = ep_strdup_printf("%s %2d, %d %02d:%02d:%02d.%09ld %s",
        	                    mon_names[tmp->tm_mon],
                	            tmp->tm_mday,
                        	    tmp->tm_year + 1900,
	                            tmp->tm_hour,
        	                    tmp->tm_min,
                	            tmp->tm_sec,
                        	    (long)abs_time->nsecs,
	                            zonename);
	                } else {
	                        buf = ep_strdup_printf("%s %2d, %d %02d:%02d:%02d.%09ld",
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
                buf = ep_strdup("Not representable");
        return buf;
}

gchar *
abs_time_secs_to_str(const time_t abs_time, const absolute_time_display_e fmt,
    gboolean show_zone)
{
        struct tm *tmp = NULL;
        const char *zonename = "???";
        gchar *buf = NULL;

#ifdef _MSC_VER
        /* calling localtime() on MSVC 2005 with huge values causes it to crash */
        /* XXX - find the exact value that still does work */
        /* XXX - using _USE_32BIT_TIME_T might be another way to circumvent this problem */
        if(abs_time > 2000000000) {
            tmp = NULL;
        } else
#endif
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
	                        buf = ep_strdup_printf("%04d/%03d:%02d:%02d:%02d %s",
        	                    tmp->tm_year + 1900,
                	            tmp->tm_yday + 1,
                        	    tmp->tm_hour,
	                            tmp->tm_min,
        	                    tmp->tm_sec,
                	            zonename);
                	} else {
	                        buf = ep_strdup_printf("%04d/%03d:%02d:%02d:%02d",
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
	                        buf = ep_strdup_printf("%s %2d, %d %02d:%02d:%02d %s",
        	                    mon_names[tmp->tm_mon],
                	            tmp->tm_mday,
                        	    tmp->tm_year + 1900,
	                            tmp->tm_hour,
        	                    tmp->tm_min,
                	            tmp->tm_sec,
                        	    zonename);
                        } else {
	                        buf = ep_strdup_printf("%s %2d, %d %02d:%02d:%02d",
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
                buf = ep_strdup("Not representable");
        return buf;
}

void
display_signed_time(gchar *buf, int buflen, const gint32 sec, gint32 frac,
    const to_str_time_res_t units)
{
	/* If the fractional part of the time stamp is negative,
	   print its absolute value and, if the seconds part isn't
	   (the seconds part should be zero in that case), stick
	   a "-" in front of the entire time stamp. */
	if (frac < 0) {
		frac = -frac;
		if (sec >= 0) {
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
		g_snprintf(buf, buflen, "%d", sec);
		break;

	case TO_STR_TIME_RES_T_DSECS:
		g_snprintf(buf, buflen, "%d.%01d", sec, frac);
		break;

	case TO_STR_TIME_RES_T_CSECS:
		g_snprintf(buf, buflen, "%d.%02d", sec, frac);
		break;

	case TO_STR_TIME_RES_T_MSECS:
		g_snprintf(buf, buflen, "%d.%03d", sec, frac);
		break;

	case TO_STR_TIME_RES_T_USECS:
		g_snprintf(buf, buflen, "%d.%06d", sec, frac);
		break;

	case TO_STR_TIME_RES_T_NSECS:
		g_snprintf(buf, buflen, "%d.%09d", sec, frac);
		break;
	}
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

/*
 * Display a relative time as days/hours/minutes/seconds.
 */
gchar *
rel_time_to_str(const nstime_t *rel_time)
{
	emem_strbuf_t *buf;
	gint32 time_val;
	gint32 nsec;

	buf=ep_strbuf_sized_new(1+TIME_SECS_LEN+1+6+1, 1+TIME_SECS_LEN+1+6+1);

	/* If the nanoseconds part of the time stamp is negative,
	   print its absolute value and, if the seconds part isn't
	   (the seconds part should be zero in that case), stick
	   a "-" in front of the entire time stamp. */
	time_val = (gint) rel_time->secs;
	nsec = rel_time->nsecs;
	if (time_val == 0 && nsec == 0) {
		ep_strbuf_append(buf, "0.000000000 seconds");
		return buf->str;
	}
	if (nsec < 0) {
		nsec = -nsec;
		ep_strbuf_append_c(buf, '-');

		/*
		 * We assume here that "rel_time->secs" is negative
		 * or zero; if it's not, the time stamp is bogus,
		 * with a positive seconds and negative microseconds.
		 */
		time_val = (gint) -rel_time->secs;
	}

	time_secs_to_str_buf(time_val, nsec, TRUE, buf);
	return buf->str;
}

#define REL_TIME_SECS_LEN	(1+10+1+9+1)

/*
 * Display a relative time as seconds.
 */
gchar *
rel_time_to_secs_str(const nstime_t *rel_time)
{
        gchar *buf;

	buf=ep_alloc(REL_TIME_SECS_LEN);

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
	int bit;
	int i;

	mask = 1;
	mask = mask << (no_of_bits-1);

	/* prepare the string */
	str=ep_alloc(256);
	str[0]='\0';
	for(bit=0;bit<((int)(bit_offset&0x07));bit++){
		if(bit&&(!(bit%4))){
			g_strlcat(str, " ", 256);
		}
		g_strlcat(str, ".", 256);
	}

	/* read the bits for the int */
	for(i=0;i<no_of_bits;i++){
		if(bit&&(!(bit%4))){
			g_strlcat(str, " ", 256);
		}
		if(bit&&(!(bit%8))){
			g_strlcat(str, " ", 256);
		}
		bit++;
		tmp = value & mask;
		if(tmp != 0){
			g_strlcat(str, "1", 256);
		} else {
			g_strlcat(str, "0", 256);
		}
		mask = mask>>1;
	}

	for(;bit%8;bit++){
		if(bit&&(!(bit%4))){
			g_strlcat(str, " ", 256);
		}
		g_strlcat(str, ".", 256);
	}
	return str;
}

/* Generate, into "buf", a string showing the bits of a bitfield.
   Return a pointer to the character after that string. */
/*XXX this needs a buf_len check */
char *
other_decode_bitfield_value(char *buf, const guint32 val, const guint32 mask, const int width)
{
  int i;
  guint32 bit;
  char *p;

  i = 0;
  p = buf;
  bit = 1 << (width - 1);
  for (;;) {
    if (mask & bit) {
      /* This bit is part of the field.  Show its value. */
      if (val & bit)
        *p++ = '1';
      else
        *p++ = '0';
    } else {
      /* This bit is not part of the field. */
      *p++ = '.';
    }
    bit >>= 1;
    i++;
    if (i >= width)
      break;
    if (i % 4 == 0)
      *p++ = ' ';
  }
  *p = '\0';
  return p;
}

char *
decode_bitfield_value(char *buf, const guint32 val, const guint32 mask, const int width)
{
  char *p;

  p = other_decode_bitfield_value(buf, val, mask, width);
  strcpy(p, " = ");
  p += 3;
  return p;
}

/* Generate a string describing a Boolean bitfield (a one-bit field that
   says something is either true or false). */
const char *
decode_boolean_bitfield(const guint32 val, const guint32 mask, const int width,
    const char *truedesc, const char *falsedesc)
{
  char *buf;
  char *p;

  buf=ep_alloc(1025); /* is this a bit overkill? */
  p = decode_bitfield_value(buf, val, mask, width);
  if (val & mask)
    strcpy(p, truedesc);
  else
    strcpy(p, falsedesc);
  return buf;
}

/* Generate a string describing a numeric bitfield (an N-bit field whose
   value is just a number). */
const char *
decode_numeric_bitfield(const guint32 val, const guint32 mask, const int width,
    const char *fmt)
{
  char *buf;
  char *p;
  int shift = 0;

  buf=ep_alloc(1025); /* isnt this a bit overkill? */
  /* Compute the number of bits we have to shift the bitfield right
     to extract its value. */
  while ((mask & (1<<shift)) == 0)
    shift++;

  p = decode_bitfield_value(buf, val, mask, width);
  g_snprintf(p, (gulong) (1025-(p-buf)), fmt, (val & mask) >> shift);
  return buf;
}

/*
 This function is very fast and this function is called a lot.
 XXX update the ep_address_to_str stuff to use this function.
*/
void
ip_to_str_buf(const guint8 *ad, gchar *buf, const int buf_len)
{
	register gchar const *p;
	register gchar *b=buf;

	if (buf_len < MAX_IP_STR_LEN) {
		g_snprintf ( buf, buf_len, BUF_TOO_SMALL_ERR );                 /* Let the unexpected value alert user */
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

gchar* guid_to_str(const e_guid_t *guid) {
  gchar *buf;

  buf=ep_alloc(GUID_STR_LEN);
  return guid_to_str_buf(guid, buf, GUID_STR_LEN);
}

gchar* guid_to_str_buf(const e_guid_t *guid, gchar *buf, int buf_len) {
  char *tempptr = buf;

  if (buf_len < GUID_STR_LEN) {
     g_strlcpy(buf, BUF_TOO_SMALL_ERR, buf_len);/* Let the unexpected value alert user */
     return buf;
  }

  /* 37 bytes */
  tempptr    = dword_to_hex(tempptr, guid->data1);		/*  8 bytes */
  *tempptr++ = '-';						/*  1 byte */
  tempptr    = word_to_hex(tempptr, guid->data2);		/*  4 bytes */
  *tempptr++ = '-';						/*  1 byte */
  tempptr    = word_to_hex(tempptr, guid->data3);		/*  4 bytes */
  *tempptr++ = '-';						/*  1 byte */
  tempptr    = bytes_to_hexstr(tempptr, &guid->data4[0], 2);	/*  4 bytes */
  *tempptr++ = '-';						/*  1 byte */
  tempptr    = bytes_to_hexstr(tempptr, &guid->data4[2], 6);	/* 12 bytes */

  *tempptr   = '\0';
  return buf;
}
