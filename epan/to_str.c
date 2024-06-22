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

static const char *
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

static char *
snprint_abs_time_secs(wmem_allocator_t *scope,
                        field_display_e fmt, struct tm *tmp,
                        const char *nsecs_str, const char *tzone_sep,
                        const char *tzone_str, bool add_quotes)
{
    char *buf;

    switch (fmt) {
        case ABSOLUTE_TIME_DOY_UTC:
            buf = wmem_strdup_printf(scope,
                    "%s%04d/%03d:%02d:%02d:%02d%s%s%s%s",
                    add_quotes ? "\"" : "",
                    tmp->tm_year + 1900,
                    tmp->tm_yday + 1,
                    tmp->tm_hour,
                    tmp->tm_min,
                    tmp->tm_sec,
                    nsecs_str,
                    tzone_sep,
                    tzone_str,
                    add_quotes ? "\"" : "");
            break;
        case ABSOLUTE_TIME_NTP_UTC:	/* FALLTHROUGH */
        case ABSOLUTE_TIME_UTC:		/* FALLTHROUGH */
        case ABSOLUTE_TIME_LOCAL:
            buf = wmem_strdup_printf(scope,
                    "%s%s %2d, %d %02d:%02d:%02d%s%s%s%s",
                    add_quotes ? "\"" : "",
                    mon_names[tmp->tm_mon],
                    tmp->tm_mday,
                    tmp->tm_year + 1900,
                    tmp->tm_hour,
                    tmp->tm_min,
                    tmp->tm_sec,
                    nsecs_str,
                    tzone_sep,
                    tzone_str,
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
    char buf_nsecs[32];
    const char *tzone_sep, *tzone_str;

    if (fmt == BASE_NONE)
        fmt = ABSOLUTE_TIME_LOCAL;

    ws_assert(FIELD_DISPLAY_IS_ABSOLUTE_TIME(fmt));

    if (fmt == ABSOLUTE_TIME_UNIX) {
        return abs_time_to_unix_str(scope, abs_time);
    }

    if (fmt == ABSOLUTE_TIME_NTP_UTC && abs_time->secs == 0 &&
                (abs_time->nsecs == 0 || abs_time->nsecs == INT_MAX)) {
        return wmem_strdup(scope, "NULL");
    }

    tmp = get_fmt_broken_down_time(fmt, &abs_time->secs);
    if (tmp == NULL) {
        return wmem_strdup(scope, "Not representable");
    }

    *buf_nsecs = '\0';
    if (abs_time->nsecs != INT_MAX) {
        snprintf(buf_nsecs, sizeof(buf_nsecs), ".%09d", abs_time->nsecs);
    }

    tzone_sep = "";
    tzone_str = "";
    if (flags & ABS_TIME_TO_STR_SHOW_ZONE || flags & ABS_TIME_TO_STR_SHOW_UTC_ONLY) {
        switch (fmt) {

        case ABSOLUTE_TIME_UTC:
        case ABSOLUTE_TIME_DOY_UTC:
        case ABSOLUTE_TIME_NTP_UTC:
            tzone_sep = " ";
            tzone_str = "UTC";
            break;

        case ABSOLUTE_TIME_LOCAL:
            if (flags & ABS_TIME_TO_STR_SHOW_ZONE) {
                tzone_sep = " ";
                tzone_str = get_zonename(tmp);
            }
            break;
        default:
            ws_assert_not_reached();
        }
    }

    return snprint_abs_time_secs(scope, fmt, tmp, buf_nsecs, tzone_sep, tzone_str, flags & ABS_TIME_TO_STR_ADD_DQUOTES);
}

char *
abs_time_secs_to_str_ex(wmem_allocator_t *scope, const time_t abs_time_secs, field_display_e fmt,
                        int flags)
{
    nstime_t abs_time;

    nstime_set_unset(&abs_time);
    abs_time.secs = abs_time_secs;
    return abs_time_to_str_ex(scope, &abs_time, fmt, flags);
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
unsigned_time_secs_to_str_buf(uint32_t time_val, const uint32_t frac,
                                const bool is_nsecs, wmem_strbuf_t *buf)
{
    int hours, mins, secs;
    bool do_comma = false;

    secs = time_val % 60;
    time_val /= 60;
    mins = time_val % 60;
    time_val /= 60;
    hours = time_val % 24;
    time_val /= 24;

    if (time_val != 0) {
        wmem_strbuf_append_printf(buf, "%u day%s", time_val, PLURALIZE(time_val));
        do_comma = true;
    }
    if (hours != 0) {
        wmem_strbuf_append_printf(buf, "%s%u hour%s", COMMA(do_comma), hours, PLURALIZE(hours));
        do_comma = true;
    }
    if (mins != 0) {
        wmem_strbuf_append_printf(buf, "%s%u minute%s", COMMA(do_comma), mins, PLURALIZE(mins));
        do_comma = true;
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

char *
unsigned_time_secs_to_str(wmem_allocator_t *scope, const uint32_t time_val)
{
    wmem_strbuf_t *buf;

    if (time_val == 0) {
        return wmem_strdup(scope, "0 seconds");
    }

    buf = wmem_strbuf_new_sized(scope, TIME_SECS_LEN+1);

    unsigned_time_secs_to_str_buf(time_val, 0, false, buf);

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
signed_time_secs_to_str_buf(int32_t time_val, const uint32_t frac,
    const bool is_nsecs, wmem_strbuf_t *buf)
{
    if(time_val < 0){
        wmem_strbuf_append_printf(buf, "-");
        if(time_val == INT32_MIN) {
            /*
             * You can't fit time_val's absolute value into
             * a 32-bit signed integer.  Just directly
             * pass UINT32_MAX, which is its absolute
             * value, directly to unsigned_time_secs_to_str_buf().
             *
             * (XXX - does ISO C guarantee that -(-2^n),
             * when calculated and cast to an n-bit unsigned
             * integer type, will have the value 2^n?)
             */
            unsigned_time_secs_to_str_buf(UINT32_MAX, frac,
                is_nsecs, buf);
        } else {
            /*
             * We now know -secs will fit into a uint32_t;
             * negate it and pass that to
             * unsigned_time_secs_to_str_buf().
             */
            unsigned_time_secs_to_str_buf(-time_val, frac, is_nsecs, buf);
        }
    } else
        unsigned_time_secs_to_str_buf(time_val, frac, is_nsecs, buf);
}

char *
signed_time_secs_to_str(wmem_allocator_t *scope, const int32_t time_val)
{
    wmem_strbuf_t *buf;

    if (time_val == 0) {
        return wmem_strdup(scope, "0 seconds");
    }

    buf = wmem_strbuf_new_sized(scope, TIME_SECS_LEN+1);

    signed_time_secs_to_str_buf(time_val, 0, false, buf);

    return wmem_strbuf_finalize(buf);
}

/*
 * Convert a signed value in milliseconds to a string, giving time in days,
 * hours, minutes, and seconds, and put the result into a buffer.
 */
char *
signed_time_msecs_to_str(wmem_allocator_t *scope, int32_t time_val)
{
    wmem_strbuf_t *buf;
    int msecs;

    if (time_val == 0) {
        return wmem_strdup(scope, "0 seconds");
    }

    buf = wmem_strbuf_new_sized(scope, TIME_SECS_LEN+1+3+1);

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

    signed_time_secs_to_str_buf(time_val, msecs, false, buf);

    return wmem_strbuf_finalize(buf);
}

/*
 * Display a relative time as days/hours/minutes/seconds.
 */
char *
rel_time_to_str(wmem_allocator_t *scope, const nstime_t *rel_time)
{
    wmem_strbuf_t *buf;
    int32_t time_val;
    int32_t nsec;

    /* If the nanoseconds part of the time stamp is negative,
       print its absolute value and, if the seconds part isn't
       (the seconds part should be zero in that case), stick
       a "-" in front of the entire time stamp. */
    time_val = (int) rel_time->secs;
    nsec = rel_time->nsecs;
    if (time_val == 0 && nsec == 0) {
        return wmem_strdup(scope, "0.000000000 seconds");
    }

    buf = wmem_strbuf_new_sized(scope, 1+TIME_SECS_LEN+1+6+1);

    if (nsec < 0) {
        nsec = -nsec;
        wmem_strbuf_append_c(buf, '-');

        /*
         * We assume here that "rel_time->secs" is negative
         * or zero; if it's not, the time stamp is bogus,
         * with a positive seconds and negative microseconds.
         */
        time_val = (int) -rel_time->secs;
    }

    signed_time_secs_to_str_buf(time_val, nsec, true, buf);

    return wmem_strbuf_finalize(buf);
}

/*
 * Number of characters required by a 64-bit signed number.
 */
#define CHARS_64_BIT_SIGNED	20	/* sign plus 19 digits */

/*
 * Number of characters required by a fractional part, in nanoseconds */
#define CHARS_NANOSECONDS	10	/* .000000001 */

/* Includes terminating '\0' */
#define NSTIME_SECS_LEN	(CHARS_64_BIT_SIGNED+CHARS_NANOSECONDS+1)

/*
 * Display a relative time as seconds.
 */
char *
rel_time_to_secs_str(wmem_allocator_t *scope, const nstime_t *rel_time)
{
    char *buf;

    buf = (char *)wmem_alloc(scope, NSTIME_SECS_LEN);

    display_signed_time(buf, NSTIME_SECS_LEN, rel_time, WS_TSPREC_NSEC);
    return buf;
}

char *
abs_time_to_unix_str(wmem_allocator_t *scope, const nstime_t *rel_time)
{
    char *buf;

    buf = (char *)wmem_alloc(scope, NSTIME_SECS_LEN);

    display_epoch_time(buf, NSTIME_SECS_LEN, rel_time, WS_TSPREC_NSEC);
    return buf;
}

/*
 * Generates a string representing the bits in a bitfield at "bit_offset" from an 8 bit boundary
 * with the length in bits of no_of_bits based on value.
 * Ex: ..xx x...
 */

char *
decode_bits_in_field(wmem_allocator_t *scope, const unsigned bit_offset, const int no_of_bits, const uint64_t value, const unsigned encoding)
{
    uint64_t mask;
    char *str;
    int bit, str_p = 0;
    int i;
    int max_bits = MIN(64, no_of_bits);
    int no_leading_dots;

    mask = UINT64_C(1) << (max_bits-1);

    if (encoding & ENC_LITTLE_ENDIAN) {
        /* Bits within octet are numbered from LSB (0) to MSB (7).
         * The value in string is from most significant bit to lowest.
         * Calculate how many dots have to be printed at the beginning of string.
         */
        no_leading_dots = (8 - ((bit_offset + no_of_bits) % 8)) % 8;
    } else {
        no_leading_dots = bit_offset % 8;
    }

    /* Prepare the string, 256 pos for the bits and zero termination, + 64 for the spaces */
    str = (char *)wmem_alloc0(scope, 256+64);
    for (bit = 0; bit < no_leading_dots; bit++) {
        if (bit && !(bit % 4)) {
            str[str_p] = ' ';
            str_p++;
        }
        str[str_p] = '.';
        str_p++;
    }

    /* read the bits for the int */
    for (i = 0; i < max_bits; i++) {
        if (bit && !(bit % 4)) {
            str[str_p] = ' ';
            str_p++;
        }
        if (bit && !(bit % 8)) {
            str[str_p] = ' ';
            str_p++;
        }
        bit++;
        if ((value & mask) != 0) {
            str[str_p] = '1';
            str_p++;
        } else {
            str[str_p] = '0';
            str_p++;
        }
        mask = mask>>1;
    }

    for (; bit % 8; bit++) {
        if (bit && !(bit % 4)) {
            str[str_p] = ' ';
            str_p++;
        }
        str[str_p] = '.';
        str_p++;
    }
    return str;
}

char *
guid_to_str(wmem_allocator_t *scope, const e_guid_t *guid)
{
    char *buf;

    buf = (char *)wmem_alloc(scope, GUID_STR_LEN);
    return guid_to_str_buf(guid, buf, GUID_STR_LEN);
}

char *
guid_to_str_buf(const e_guid_t *guid, char *buf, int buf_len)
{
    char *tempptr = buf;

    if (buf_len < GUID_STR_LEN) {
        (void) g_strlcpy(buf, BUF_TOO_SMALL_ERR, buf_len); /* Let the unexpected value alert user */
        return buf;
    }

    /* 37 bytes */
    tempptr    = dword_to_hex(tempptr, guid->data1);        /*  8 bytes */
    *tempptr++ = '-';                                       /*  1 byte */
    tempptr    = word_to_hex(tempptr, guid->data2);         /*  4 bytes */
    *tempptr++ = '-';                                       /*  1 byte */
    tempptr    = word_to_hex(tempptr, guid->data3);         /*  4 bytes */
    *tempptr++ = '-';                                       /*  1 byte */
    tempptr    = bytes_to_hexstr(tempptr, &guid->data4[0], 2);  /*  4 bytes */
    *tempptr++ = '-';                                       /*  1 byte */
    tempptr    = bytes_to_hexstr(tempptr, &guid->data4[2], 6);  /* 12 bytes */

    *tempptr   = '\0';
    return buf;
}

const char *
port_type_to_str (port_type type)
{
    switch (type) {
        case PT_NONE:       return "NONE";
        case PT_SCTP:       return "SCTP";
        case PT_TCP:        return "TCP";
        case PT_UDP:        return "UDP";
        case PT_DCCP:       return "DCCP";
        case PT_IPX:        return "IPX";
        case PT_DDP:        return "DDP";
        case PT_IDP:        return "IDP";
        case PT_USB:        return "USB";
        case PT_I2C:        return "I2C";
        case PT_IBQP:       return "IBQP";
        case PT_BLUETOOTH:  return "BLUETOOTH";
        case PT_IWARP_MPA:  return "IWARP_MPA";
        default:            return "[Unknown]";
    }
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
