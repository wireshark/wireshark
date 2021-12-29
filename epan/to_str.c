/* to_str.c
 * Routines for utilities to convert various other types to strings.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <glib.h>

#include <epan/wmem_scopes.h>
#include "proto.h"
#include "to_str.h"
#include "strutil.h"
#include <wsutil/pint.h>
#include <wsutil/utf8_entities.h>

/*
 * If a user _does_ pass in a too-small buffer, this is probably
 * going to be too long to fit.  However, even a partial string
 * starting with "[Buf" should provide enough of a clue to be
 * useful.
 */
#define BUF_TOO_SMALL_ERR "[Buffer too small]"

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
	/*
	 * The strings in _tzname[] are encoded using the code page
	 * for the current C-language locale.
	 *
	 * On Windows, all Wireshark programs set that code page
	 * to the UTF-8 code page by calling
	 *
	 *	  setlocale(LC_ALL, ".UTF-8");
	 *
	 * so the strings in _tzname[] are UTF-8 strings, and we can
	 * just return them.
	 *
	 * (Note: the above does *not* mean we've set any code pages
	 * *other* than the one used by the Visual Studio C runtime
	 * to UTF-8, so don't assume, for example, that the "ANSI"
	 * versions of Windows APIs will take UTF-8 strings, or that
	 * non-UTF-16 output to the console will be treated as UTF-8.
	 * Setting those other code pages can cause problems, especially
	 * on pre-Windows 10 or older Windows 10 releases.)
	 */
	return _tzname[tmp->tm_isdst];
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

static struct tm *
get_fmt_broken_down_time(field_display_e fmt, const time_t *secs)
{
	switch (fmt) {
		case ABSOLUTE_TIME_UTC:
		case ABSOLUTE_TIME_DOY_UTC:
		case ABSOLUTE_TIME_NTP_UTC:
			return gmtime(secs);
		case ABSOLUTE_TIME_LOCAL:
			return localtime(secs);
		default:
			break;
	}
	ws_assert_not_reached();
}

static const char *
get_fmt_zonename(field_display_e fmt, struct tm *tmp)
{
	switch (fmt) {
		case ABSOLUTE_TIME_UTC:
		case ABSOLUTE_TIME_DOY_UTC:
		case ABSOLUTE_TIME_NTP_UTC:
			return "UTC";
		case ABSOLUTE_TIME_LOCAL:
			return get_zonename(tmp);
		default:
			break;
	}
	ws_assert_not_reached();
}

static char *
snprint_abs_time_secs(wmem_allocator_t *scope, field_display_e fmt,
				struct tm *tmp, const char *trailer,
				gboolean add_quotes)
{
	char *buf;

	switch (fmt) {
		case ABSOLUTE_TIME_DOY_UTC:
			buf = wmem_strdup_printf(scope,
					"%s%04d/%03d:%02d:%02d:%02d%s%s",
					add_quotes ? "\"" : "",
					tmp->tm_year + 1900,
					tmp->tm_yday + 1,
					tmp->tm_hour,
					tmp->tm_min,
					tmp->tm_sec,
					trailer,
					add_quotes ? "\"" : "");
			break;
		case ABSOLUTE_TIME_NTP_UTC:	/* FALLTHROUGH */
		case ABSOLUTE_TIME_UTC:		/* FALLTHROUGH */
		case ABSOLUTE_TIME_LOCAL:
			buf = wmem_strdup_printf(scope,
					"%s%s %2d, %d %02d:%02d:%02d%s%s",
					add_quotes ? "\"" : "",
					mon_names[tmp->tm_mon],
					tmp->tm_mday,
					tmp->tm_year + 1900,
					tmp->tm_hour,
					tmp->tm_min,
					tmp->tm_sec,
					trailer,
					add_quotes ? "\"" : "");
			break;
		default:
			ws_assert_not_reached();
	}
	return buf;
}

char *
abs_time_to_str_ex(wmem_allocator_t *scope, const nstime_t *abs_time, field_display_e fmt,
			int flags)
{
	struct tm *tmp;
	char buf_trailer[64];

	ws_assert(FIELD_DISPLAY_IS_ABSOLUTE_TIME(fmt));

	if (fmt == ABSOLUTE_TIME_NTP_UTC && nstime_is_zero(abs_time)) {
		return wmem_strdup(scope, "NULL");
	}

	tmp = get_fmt_broken_down_time(fmt, &abs_time->secs);
	if (tmp == NULL) {
		return wmem_strdup(scope, "Not representable");
	}

	if (flags & ABS_TIME_TO_STR_SHOW_ZONE)
		snprintf(buf_trailer, sizeof(buf_trailer), ".%09d %s", abs_time->nsecs, get_fmt_zonename(fmt, tmp));
	else
		snprintf(buf_trailer, sizeof(buf_trailer), ".%09d", abs_time->nsecs);

	return snprint_abs_time_secs(scope, fmt, tmp, buf_trailer, flags & ABS_TIME_TO_STR_ADD_DQUOTES);
}

char *
abs_time_secs_to_str_ex(wmem_allocator_t *scope, const time_t abs_time_secs, field_display_e fmt,
			int flags)
{
	struct tm *tmp;
	char buf_trailer[64];

	ws_assert(FIELD_DISPLAY_IS_ABSOLUTE_TIME(fmt));

	if (fmt == ABSOLUTE_TIME_NTP_UTC && abs_time_secs == 0) {
		return wmem_strdup(scope, "NULL");
	}

	tmp = get_fmt_broken_down_time(fmt, &abs_time_secs);
	if (tmp == NULL) {
		return wmem_strdup(scope, "Not representable");
	}

	if (flags & ABS_TIME_TO_STR_SHOW_ZONE)
		snprintf(buf_trailer, sizeof(buf_trailer), " %s", get_fmt_zonename(fmt, tmp));
	else
		*buf_trailer = '\0';

	return snprint_abs_time_secs(scope, fmt, tmp, buf_trailer, flags & ABS_TIME_TO_STR_ADD_DQUOTES);
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
			snprintf(buf, buflen, "%0.0f", elapsed_secs);
			break;

		case TO_STR_TIME_RES_T_DSECS:
			snprintf(buf, buflen, "%0.0f.%01d", elapsed_secs, frac);
			break;

		case TO_STR_TIME_RES_T_CSECS:
			snprintf(buf, buflen, "%0.0f.%02d", elapsed_secs, frac);
			break;

		case TO_STR_TIME_RES_T_MSECS:
			snprintf(buf, buflen, "%0.0f.%03d", elapsed_secs, frac);
			break;

		case TO_STR_TIME_RES_T_USECS:
			snprintf(buf, buflen, "%0.0f.%06d", elapsed_secs, frac);
			break;

		case TO_STR_TIME_RES_T_NSECS:
			snprintf(buf, buflen, "%0.0f.%09d", elapsed_secs, frac);
			break;
	}
}

/*
 * Number of characters required by a 64-bit signed number.
 */
#define CHARS_64_BIT_SIGNED	20	/* sign plus 19 digits */

/*
 * Number of characters required by a fractional part, in nanoseconds */
#define CHARS_NANOSECONDS	10	/* .000000001 */

void
display_signed_time(gchar *buf, int buflen, const gint64 sec, gint32 frac,
		const to_str_time_res_t units)
{
	/* this buffer is not NUL terminated */
	gint8 num_buf[CHARS_64_BIT_SIGNED];
	gint8 *num_end = &num_buf[CHARS_64_BIT_SIGNED];
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

	num_ptr = int64_to_str_back(num_end, sec);

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

/* Includes terminating '\0' */
#define REL_TIME_SECS_LEN	(CHARS_64_BIT_SIGNED+CHARS_NANOSECONDS+1)

/*
 * Display a relative time as seconds.
 */
gchar *
rel_time_to_secs_str(wmem_allocator_t *scope, const nstime_t *rel_time)
{
	gchar *buf;

	buf=(gchar *)wmem_alloc(scope, REL_TIME_SECS_LEN);

	display_signed_time(buf, REL_TIME_SECS_LEN, (gint64) rel_time->secs,
			rel_time->nsecs, TO_STR_TIME_RES_T_NSECS);
	return buf;
}

/*
 * Generates a string representing the bits in a bitfield at "bit_offset" from an 8 bit boundary
 * with the length in bits of no_of_bits based on value.
 * Ex: ..xx x...
 */

char *
decode_bits_in_field(wmem_allocator_t *scope, const guint bit_offset, const gint no_of_bits, const guint64 value, const guint encoding)
{
	guint64 mask;
	char *str;
	int bit, str_p = 0;
	int i;
	int max_bits = MIN(64, no_of_bits);
	int no_leading_dots;

	mask = G_GUINT64_CONSTANT(1) << (max_bits-1);

	if(encoding & ENC_LITTLE_ENDIAN){
		/* Bits within octet are numbered from LSB (0) to MSB (7).
		 * The value in string is from most significant bit to lowest.
		 * Calculate how many dots have to be printed at the beginning of string.
		 */
		no_leading_dots = (8 - ((bit_offset + no_of_bits) % 8)) % 8;
	} else {
		no_leading_dots = bit_offset % 8;
	}

	/* Prepare the string, 256 pos for the bits and zero termination, + 64 for the spaces */
	str=(char *)wmem_alloc0(scope, 256+64);
	for(bit=0;bit<no_leading_dots;bit++){
		if(bit&&(!(bit%4))){
			str[str_p] = ' ';
			str_p++;
		}
		str[str_p] = '.';
		str_p++;
	}

	/* read the bits for the int */
	for(i=0;i<max_bits;i++){
		if(bit&&(!(bit%4))){
			str[str_p] = ' ';
			str_p++;
		}
		if(bit&&(!(bit%8))){
			str[str_p] = ' ';
			str_p++;
		}
		bit++;
		if((value & mask) != 0){
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
		(void) g_strlcpy(buf, BUF_TOO_SMALL_ERR, buf_len);/* Let the unexpected value alert user */
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
		case PT_DDP:		return "DDP";
		case PT_IDP:		return "IDP";
		case PT_USB:		return "USB";
		case PT_I2C:		return "I2C";
		case PT_IBQP:		return "IBQP";
		case PT_BLUETOOTH:	return "BLUETOOTH";
		case PT_IWARP_MPA:	return "IWARP_MPA";
		default:		return "[Unknown]";
	}
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
